
/// Retrieve the AoR data for a given SIP URI, creating it if there isn't
/// any already.
bool MemcachedStore::get(const std::string& namespace,
                         const std::string& key,
                         std::string& data)
                                  ///< the SIP URI
{
  memcached_return_t rc = MEMCACHED_ERROR;
  MemcachedAoR* aor_data = NULL;
  memcached_result_st result;
  std::vector<bool> read_repair(_replicas);
  size_t failed_replicas = 0;
  const char* key_ptr = aor_id.data();
  const size_t key_len = aor_id.length();

  const std::vector<memcached_st*>& replicas = get_replicas(aor_id, Op::READ);
  LOG_DEBUG("%d read replicas for key %s", replicas.size(), aor_id.c_str());

  // Read from all replicas until we get a positive result.
  size_t ii;
  for (ii = 0; ii < replicas.size(); ++ii)
  {
    LOG_DEBUG("Attempt to read from replica %d (connection %p)", ii, replicas[ii]);
    rc = memcached_mget(replicas[ii], &key_ptr, &key_len, 1);

    if (memcached_success(rc))
    {
      memcached_result_create(replicas[ii], &result);
      memcached_fetch_result(replicas[ii], &result, &rc);
    }

    if (memcached_success(rc))
    {
      // Found a record, so exit
      LOG_DEBUG("Found record on replica %d", ii);
      break;
    }
    else if (rc == MEMCACHED_NOTFOUND)
    {
      // Failed to find a record on an active replica, so flag that we may
      // need to do a read repair to this node.
      LOG_DEBUG("Read for %s on replica %d returned NOTFOUND", aor_id.c_str(), ii);
      read_repair[ii] = true;
      memcached_result_free(&result);
    }
    else
    {
      // Error from this node, so consider it inactive.
      LOG_DEBUG("Read for %s on replica %d returned error %d (%s)",
                aor_id.c_str(), ii, rc, memcached_strerror(replicas[ii], rc));
      ++failed_replicas;
    }
  }

  if (memcached_success(rc))
  {
    // Deserialize the result and expire any bindings that are out of date.
    LOG_DEBUG("Deserialize record");
    aor_data = deserialize_aor(std::string(memcached_result_value(&result), memcached_result_length(&result)));
    aor_data->set_cas(memcached_result_cas(&result));
    int now = time(NULL);
    int max_expires = expire_bindings(aor_data, now);

    // See if we need to do a read repair on any nodes that didn't find the record.
    bool first_repair = true;
    for (size_t jj = 0; jj < ii; ++jj)
    {
      if (read_repair[jj])
      {
        if (max_expires > now)
        {
          LOG_INFO("Do read repair for %s on replica %d, expiry = %d", aor_id.c_str(), jj, max_expires - now);
          if (first_repair)
          {
            LOG_DEBUG("First repair replica, so must do synchronous add");
            memcached_return_t repair_rc;
            repair_rc = memcached_add(replicas[jj],
                                      key_ptr,
                                      key_len,
                                      memcached_result_value(&result),
                                      memcached_result_length(&result),
                                      max_expires,
                                      0);
            if (memcached_success(repair_rc))
            {
              // Read repair worked, but we have to do another read to get the
              // CAS value on the primary server.
              LOG_DEBUG("Read repair on replica %d successful", jj);
              repair_rc = memcached_mget(replicas[jj], &key_ptr, &key_len, 1);

              if (memcached_success(repair_rc))
              {
                memcached_result_st repaired_result;
                memcached_result_create(replicas[jj], &repaired_result);
                memcached_fetch_result(replicas[jj], &repaired_result, &repair_rc);
                if (memcached_success(repair_rc))
                {
                  LOG_DEBUG("Updating CAS value on AoR record from %ld to %ld",
                            aor_data->get_cas(),
                            memcached_result_cas(&repaired_result));
                  aor_data->set_cas(memcached_result_cas(&repaired_result));
                }
                memcached_result_free(&repaired_result);
              }

              if (!memcached_success(repair_rc))
              {
                // Failed to read data after a successful read repair.  There's
                // not much we can do about this error - it will likely mean a
                // subsequent write will fail because the CAS value will be
                // wrong, but the app should then retry.
                LOG_WARNING("Failed to read data for %s from replica %d after successful read repair, rc = %d (%s)",
                            aor_id.c_str(),
                            jj,
                            repair_rc,
                            memcached_strerror(replicas[jj], repair_rc));
              }

              first_repair = true;
            }
          }
          else
          {
            // Not the first read repair, so can just do the add asynchronously
            // on a best efforts basis.
            LOG_DEBUG("Not first repair replica, so do asynchronous add");
            memcached_behavior_set(replicas[jj], MEMCACHED_BEHAVIOR_NOREPLY, 1);
            memcached_add(replicas[jj],
                          key_ptr,
                          key_len,
                          memcached_result_value(&result),
                          memcached_result_length(&result),
                          max_expires,
                          0);
            memcached_behavior_set(replicas[jj], MEMCACHED_BEHAVIOR_NOREPLY, 0);
          }
        }
        else
        {
          // We would do a read repair here, but the record has expired so
          // there is no point.  To make sure the next write is successful
          // we need to set the CAS value on the record we are about to return
          // to zero so the write will be processed as an add, not a cas.
          LOG_DEBUG("Force CAS to zero on expired record");
          aor_data->set_cas(0);
        }
      }
    }

    // Free the result.
    memcached_result_free(&result);
  }
  else if (failed_replicas < replicas.size())
  {
    // At least one replica returned NOT_FOUND, so return an empty aor_data
    // record
    LOG_DEBUG("At least one replica returned not found, so return empty record");
    aor_data = new MemcachedAoR();
  }
  else
  {
    // All replicas returned an error, so return no data record and log the
    // error.
    LOG_ERROR("Failed to read AoR data for %s from %d replicas",
              aor_id.c_str(), replicas.size());
  }

  return (AoR*)aor_data;
}


/// Update the data for a particular address of record.  Writes the data
/// atomically.  If the underlying data has changed since it was last
/// read, the update is rejected and this returns false; if the update
/// succeeds, this returns true.
bool MemcachedStore::set_aor_data(const std::string& aor_id,
                                  ///< the SIP URI
                                  AoR* data)
                                  ///< the data to store
{
  memcached_return_t rc = MEMCACHED_ERROR;
  MemcachedAoR* aor_data = (MemcachedAoR*)data;
  const char* key_ptr = aor_id.data();
  const size_t key_len = aor_id.length();

  const std::vector<memcached_st*>& replicas = get_replicas(aor_id, Op::WRITE);
  LOG_DEBUG("%d write replicas for key %s", replicas.size(), aor_id.c_str());

  // Expire any old bindings before writing to the server.  In theory,
  // if there are no bindings left we could delete the entry, but this
  // may cause concurrency problems because memcached does not support
  // cas on delete operations.  In this case we do a memcached_cas with
  // an effectively immediate expiry time.
  int now = time(NULL);
  int max_expires = expire_bindings(aor_data, now);
  std::string value = serialize_aor(aor_data);

  // First try to write the primary data record to the first responding
  // server.
  size_t ii;
  for (ii = 0; ii < replicas.size(); ++ii)
  {
    LOG_DEBUG("Attempt conditional write to replica %d (connection %p), CAS = %ld",
              ii,
              replicas[ii],
              aor_data->get_cas());

    if (aor_data->get_cas() == 0)
    {
      // New record, so attempt to add.  This will fail if someone else
      // gets there first.
      rc = memcached_add(replicas[ii],
                         key_ptr,
                         key_len,
                         value.data(),
                         value.length(),
                         max_expires,
                         0);
    }
    else
    {
      // This is an update to an existing record, so use memcached_cas
      // to make sure it is atomic.
      rc = memcached_cas(replicas[ii],
                         key_ptr,
                         key_len,
                         value.data(),
                         value.length(),
                         max_expires,
                         0,
                         aor_data->get_cas());
    }

    if (memcached_success(rc))
    {
      LOG_DEBUG("Conditional write succeeded to replica %d", ii);
      break;
    }
    else
    {
      LOG_DEBUG("memcached_%s command for %s failed on replica %d, rc = %d (%s), expiry = %d",
                (aor_data->get_cas() == 0) ? "add" : "cas",
                aor_id.c_str(),
                ii,
                rc,
                memcached_strerror(replicas[ii], rc),
                max_expires - now);

      if ((rc == MEMCACHED_NOTSTORED) ||
          (rc == MEMCACHED_DATA_EXISTS))
      {
        // A NOT_STORED or EXISTS response indicates a concurrent write failure,
        // so return this to the application immediately - don't go on to
        // other replicas.
        LOG_INFO("Contention writing data for %s to store", aor_id.c_str());
        break;
      }
    }
  }

  if ((rc == MEMCACHED_SUCCESS) &&
      (ii < replicas.size()))
  {
    // Write has succeeded, so write unconditionally (and asynchronously)
    // to the replicas.
    for (size_t jj = ii + 1; jj < replicas.size(); ++jj)
    {
      LOG_DEBUG("Attempt unconditional write to replica %d", jj);
      memcached_behavior_set(replicas[jj], MEMCACHED_BEHAVIOR_NOREPLY, 1);
      memcached_set(replicas[jj],
                    key_ptr,
                    key_len,
                    value.data(),
                    value.length(),
                    max_expires,
                    0);
      memcached_behavior_set(replicas[jj], MEMCACHED_BEHAVIOR_NOREPLY, 0);
    }
  }

  if ((!memcached_success(rc)) &&
      (rc != MEMCACHED_NOTSTORED) &&
      (rc != MEMCACHED_DATA_EXISTS))
  {
    LOG_ERROR("Failed to write AoR data for %s to %d replicas",
              aor_id.c_str(), replicas.size());
  }

  return memcached_success(rc);
}

// LCOV_EXCL_STOP


/// Serialize the contents of an AoR.
std::string MemcachedStore::serialize_aor(MemcachedAoR* aor_data)
{
  std::ostringstream oss(std::ostringstream::out|std::ostringstream::binary);

  int num_bindings = aor_data->bindings().size();
  oss.write((const char *)&num_bindings, sizeof(int));

  for (AoR::Bindings::const_iterator i = aor_data->bindings().begin();
       i != aor_data->bindings().end();
       ++i)
  {
    oss << i->first << '\0';

    AoR::Binding* b = i->second;
    oss << b->_uri << '\0';
    oss << b->_cid << '\0';
    oss.write((const char *)&b->_cseq, sizeof(int));
    oss.write((const char *)&b->_expires, sizeof(int));
    oss.write((const char *)&b->_priority, sizeof(int));
    int num_params = b->_params.size();
    oss.write((const char *)&num_params, sizeof(int));
    for (std::list<std::pair<std::string, std::string> >::const_iterator i = b->_params.begin();
         i != b->_params.end();
         ++i)
    {
      oss << i->first << '\0' << i->second << '\0';
    }
    int num_path_hdrs = b->_path_headers.size();
    oss.write((const char *)&num_path_hdrs, sizeof(int));
    for (std::list<std::string>::const_iterator i = b->_path_headers.begin();
         i != b->_path_headers.end();
         ++i)
    {
      oss << *i << '\0';
    }
  }

  return oss.str();
}


/// Deserialize the contents of an AoR
MemcachedAoR* MemcachedStore::deserialize_aor(const std::string& s)
{
  std::istringstream iss(s, std::istringstream::in|std::istringstream::binary);

  MemcachedAoR* aor_data = new MemcachedAoR();
  int num_bindings;
  iss.read((char *)&num_bindings, sizeof(int));
  LOG_DEBUG("There are %d bindings", num_bindings);

  for (int ii = 0; ii < num_bindings; ++ii)
  {
    // Extract the binding identifier into a string.
    std::string binding_id;
    getline(iss, binding_id, '\0');

    AoR::Binding* b = aor_data->get_binding(binding_id);

    // Now extract the various fixed binding parameters.
    getline(iss, b->_uri, '\0');
    getline(iss, b->_cid, '\0');
    iss.read((char *)&b->_cseq, sizeof(int));
    iss.read((char *)&b->_expires, sizeof(int));
    iss.read((char *)&b->_priority, sizeof(int));

    int num_params;
    iss.read((char *)&num_params, sizeof(int));
    LOG_DEBUG("Binding has %d params", num_params);
    b->_params.resize(num_params);
    for (std::list<std::pair<std::string, std::string> >::iterator i = b->_params.begin();
         i != b->_params.end();
         ++i)
    {
      getline(iss, i->first, '\0');
      getline(iss, i->second, '\0');
      LOG_DEBUG("Read param %s = %s", i->first.c_str(), i->second.c_str());
    }

    int num_paths = 0;
    iss.read((char *)&num_paths, sizeof(int));
    b->_path_headers.resize(num_paths);
    LOG_DEBUG("Binding has %d paths", num_paths);
    for (std::list<std::string>::iterator i = b->_path_headers.begin();
         i != b->_path_headers.end();
         ++i)
    {
      getline(iss, *i, '\0');
      LOG_DEBUG("Read path %s", i->c_str());
    }
  }

  return aor_data;
}


