/**
 * @file memcachedstoreview_test.cpp UT for Memcached redundancy algorithm
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2014 Metaswitch Networks Ltd
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version, along with the "Special Exception" for use of
 * the program along with SSL, set forth below. This program is distributed
 * in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details. You should have received a copy of the GNU General Public
 * License along with this program.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * The author can be reached by email at clearwater@metaswitch.com or by
 * post at Metaswitch Networks Ltd, 100 Church St, Enfield EN2 6BQ, UK
 *
 * Special Exception
 * Metaswitch Networks Ltd  grants you permission to copy, modify,
 * propagate, and distribute a work formed by combining OpenSSL with The
 * Software, or a work derivative of such a combination, even if such
 * copying, modification, propagation, or distribution would otherwise
 * violate the terms of the GPL. You must comply with the GPL in all
 * respects for all of the code used other than OpenSSL.
 * "OpenSSL" means OpenSSL toolkit software distributed by the OpenSSL
 * Project and licensed under the OpenSSL Licenses, or a work based on such
 * software and licensed under the OpenSSL Licenses.
 * "OpenSSL Licenses" means the OpenSSL License and Original SSLeay License
 * under which the OpenSSL Project distributes the OpenSSL toolkit software,
 * as those licenses appear in the file LICENSE-OPENSSL.
 */


#include <string>
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include <json/reader.h>
#include <set>
#include <algorithm>

#include "utils.h"
#include "sas.h"
#include "memcachedstoreview.h"
#include "avstore.h"
#include "test_utils.hpp"
#include "test_interposer.hpp"

using namespace std;

class MemcachedViewTest : public ::testing::Test
{
  MemcachedViewTest()
  {
  }

  virtual ~MemcachedViewTest()
  {
  }

  virtual void SetUp()
  {
    _num_vbuckets = 128;
    _num_replicas = 2;
    _view = new MemcachedStoreView(_num_vbuckets, _num_replicas);
  }

  virtual void TearDown()
  {
    delete _view;
  }

  // Common function that ensures that scaling up works, and checks
  // the properties that are necessary for preserving redundancy while
  // and after scaling. Most of the other tests just feed different
  // initial and final sets of servers into this algorithm, to check
  // that redundancy is preserved in a variety of scaling topologies.
  void common_scaling_assertions(vector<string> servers, vector<string> new_servers)
  {
    vector<string> empty = {};

    _view->update(servers, empty);

    vector<vector<string>> initial_read_set = get_current_read_set();
    vector<vector<string>> initial_write_set = get_current_write_set();

    _view->update(servers, new_servers);

    vector<vector<string>> new_read_set = get_current_read_set();
    vector<vector<string>> new_write_set = get_current_write_set();

    // Our read set should contain all the servers we would have written
    // to before scaling up.
    ASSERT_TRUE(all_vbuckets_are_superset(new_read_set, initial_write_set));

    // It should also contain all the servers we are currently writing to.
    ASSERT_TRUE(all_vbuckets_are_superset(new_read_set, new_write_set));

    _view->update(new_servers, empty);

    vector<vector<string>> final_read_set = get_current_read_set();
    vector<vector<string>> final_write_set = get_current_write_set();

    // Our write set while scaling up should have written to all the
    // servers we might read from after scaling up, to ensure redundancy.
    ASSERT_TRUE(all_vbuckets_are_superset(new_write_set, final_read_set));

    // And now that we're in a stable state, our readers should match
    // our writers again.
    for (size_t ii = 0; ii < _num_vbuckets; ii++)
    {
      ASSERT_EQ(_view->read_replicas(ii), _view->write_replicas(ii));
    }
  }

  bool is_subset(vector<string> set1, vector<string> set2)
  {
    vector<string> overlap;
    sort(set1.begin(), set1.end());
    sort(set2.begin(), set2.end());
    set_difference(set1.begin(), set1.end(), set2.begin(), set2.end(), back_inserter(overlap));
    return overlap.empty();
  }

  bool is_superset(vector<string> set1, vector<string> set2)
  {
    return is_subset(set2, set1);
  }

  bool all_vbuckets_are_superset(vector<vector<string>> set1, vector<vector<string>> set2)
  {
    assert(set1.size() == set2.size());
    for (size_t ii = 0; ii < set1.size(); ii++)
    {
      if (!is_superset(set1[ii], set2[ii]))
      {
        return false;
      }
    }
    return true;
  }

  vector<vector<string>> get_current_read_set()
  {
    vector<vector<string>> read_set;
    read_set.resize(_num_vbuckets);
    for (size_t ii = 0; ii < _num_vbuckets; ii++)
    {
      read_set[ii] = _view->read_replicas(ii);
    }
    return read_set;
  }

  vector<vector<string>> get_current_write_set()
  {
    vector<vector<string>> write_set;
    write_set.resize(_num_vbuckets);
    for (size_t ii = 0; ii < _num_vbuckets; ii++)
    {
      write_set[ii] = _view->write_replicas(ii);
    }
    return write_set;
  }

  MemcachedStoreView* _view;
  size_t _num_vbuckets;
  size_t _num_replicas;
};

class MemcachedViewTwentyReplicasTest : public MemcachedViewTest
{
  virtual void SetUp()
  {
    _num_vbuckets = 128;
    _num_replicas = 20;
    _view = new MemcachedStoreView(_num_vbuckets, _num_replicas);
  }

  virtual void TearDown()
  {
    delete _view;
  }
};

class MemcachedViewElevenVbucketsTest : public MemcachedViewTest
{
  virtual void SetUp()
  {
    _num_vbuckets = 11;
    _num_replicas = 2;
    _view = new MemcachedStoreView(_num_vbuckets, _num_replicas);
  }

  virtual void TearDown()
  {
    delete _view;
  }
};

TEST_F(MemcachedViewTest, ReadersAndWritersMatch)
{
  vector<string> servers = {"1.2.3.4", "1.2.3.5", "1.2.3.6"};
  vector<string> empty = {};

  _view->update(servers, empty);

  for (size_t ii = 0; ii < _num_vbuckets; ii++)
  {
    ASSERT_EQ(_view->read_replicas(ii), _view->write_replicas(ii));
  }
}

TEST_F(MemcachedViewTest, ReplicasAreHonoured)
{
  vector<string> servers = {"1.2.3.4", "1.2.3.5", "1.2.3.6"};
  vector<string> empty = {};

  _view->update(servers, empty);

  // We should be writing and reading at the desired level of redundancy.
  for (size_t ii = 0; ii < _num_vbuckets; ii++)
  {
    ASSERT_EQ(_view->read_replicas(ii).size(), _num_replicas);
    ASSERT_EQ(_view->write_replicas(ii).size(), _num_replicas);
  }
}

TEST_F(MemcachedViewTwentyReplicasTest, ReplicasAreHonoured)
{
  vector<string> servers = {"1.2.3.1", "1.2.3.2", "1.2.3.3", "1.2.3.4", "1.2.3.5", "1.2.3.6", "1.2.3.7", "1.2.3.8", "1.2.3.9", "1.2.3.10", "1.2.3.11", "1.2.3.12", "1.2.3.13", "1.2.3.14", "1.2.3.15", "1.2.3.16", "1.2.3.17", "1.2.3.18", "1.2.3.19", "1.2.3.20"}; 
  vector<string> empty = {};

  _view->update(servers, empty);

  // We should be writing and reading at the desired level of redundancy.
  for (size_t ii = 0; ii < _num_vbuckets; ii++)
  {
    ASSERT_EQ(_view->read_replicas(ii).size(), _num_replicas);
    ASSERT_EQ(_view->write_replicas(ii).size(), _num_replicas);
  }
}

class MemcachedViewScaleUpTest : public MemcachedViewTest {};

TEST_F(MemcachedViewScaleUpTest, AppendingServers)
{
  vector<string> servers = {"1.2.3.4", "1.2.3.5", "1.2.3.6"};
  vector<string> new_servers = {"1.2.3.4", "1.2.3.5", "1.2.3.6", "1.2.3.7", "1.2.3.8"};
  common_scaling_assertions(servers, new_servers);
}

TEST_F(MemcachedViewScaleUpTest, PrependingServers)
{
  vector<string> servers = {"1.2.3.4", "1.2.3.5", "1.2.3.6"};
  vector<string> new_servers = {"1.2.3.7", "1.2.3.8", "1.2.3.4", "1.2.3.5", "1.2.3.6"};
  common_scaling_assertions(servers, new_servers);
}

TEST_F(MemcachedViewScaleUpTest, IntermixingServers)
{
  vector<string> servers = {"1.2.3.4", "1.2.3.5", "1.2.3.6"};
  vector<string> new_servers = {"1.2.3.4", "1.2.3.7", "1.2.3.5", "1.2.3.8", "1.2.3.6"};
  common_scaling_assertions(servers, new_servers);
}

TEST_F(MemcachedViewScaleUpTest, DifferentServers)
{
  vector<string> servers = {"1.2.3.4", "1.2.3.5", "1.2.3.6"};
  vector<string> new_servers = {"1.2.3.7", "1.2.3.8", "1.2.3.9", "1.2.3.10", "1.2.3.11"};
  common_scaling_assertions(servers, new_servers);
}

class MemcachedViewScaleDownTest : public MemcachedViewTest {};

TEST_F(MemcachedViewScaleDownTest, RemovingEndServers)
{
  vector<string> servers = {"1.2.3.4", "1.2.3.5", "1.2.3.6", "1.2.3.7", "1.2.3.8"};
  vector<string> new_servers = {"1.2.3.4", "1.2.3.5", "1.2.3.6",};
  common_scaling_assertions(servers, new_servers);
}

TEST_F(MemcachedViewScaleDownTest, RemovingInitialServers)
{
  vector<string> servers = {"1.2.3.4", "1.2.3.5", "1.2.3.6", "1.2.3.7", "1.2.3.8"};
  vector<string> new_servers = {"1.2.3.6", "1.2.3.7", "1.2.3.8",};
  common_scaling_assertions(servers, new_servers);
}

TEST_F(MemcachedViewScaleDownTest, RemovingMiddleServers)
{
  vector<string> servers = {"1.2.3.4", "1.2.3.5", "1.2.3.6", "1.2.3.7", "1.2.3.8"};
  vector<string> new_servers = {"1.2.3.4", "1.2.3.8"};
  common_scaling_assertions(servers, new_servers);
}

TEST_F(MemcachedViewScaleDownTest, NewServers)
{
  vector<string> servers = {"1.2.3.4", "1.2.3.5", "1.2.3.6", "1.2.3.7", "1.2.3.8"};
  vector<string> new_servers = {"1.2.3.9", "1.2.3.10"};
  common_scaling_assertions(servers, new_servers);
}

class MemcachedViewScaleAcrossTest : public MemcachedViewTest {};

TEST_F(MemcachedViewScaleAcrossTest, IdenticalServers)
{
  vector<string> servers = {"1.2.3.4", "1.2.3.5", "1.2.3.6",};
  vector<string> new_servers = {"1.2.3.4", "1.2.3.5", "1.2.3.6",};
  common_scaling_assertions(servers, new_servers);
}

TEST_F(MemcachedViewScaleAcrossTest, ReorderingServers)
{
  vector<string> servers = {"1.2.3.4", "1.2.3.5", "1.2.3.6",};
  vector<string> new_servers = {"1.2.3.6", "1.2.3.4", "1.2.3.5",};
  common_scaling_assertions(servers, new_servers);
}

TEST_F(MemcachedViewScaleAcrossTest, NewServers)
{
  vector<string> servers = {"1.2.3.4", "1.2.3.5", "1.2.3.6",};
  vector<string> new_servers = {"1.2.3.7", "1.2.3.8", "1.2.3.9",};
  common_scaling_assertions(servers, new_servers);
}

// Minimal testing of edge cases - Sprout always uses 128 vbuckets and
// two replicas, but it's good to test the generality of the algorithm.

class MemcachedViewTwentyReplicasScaleUpTest : public MemcachedViewTwentyReplicasTest {};
class MemcachedViewTwentyReplicasScaleDownTest : public MemcachedViewTwentyReplicasTest {};
class MemcachedViewElevenVbucketsScaleUpTest : public MemcachedViewElevenVbucketsTest {};
class MemcachedViewElevenVbucketsScaleDownTest : public MemcachedViewElevenVbucketsTest {};

TEST_F(MemcachedViewTwentyReplicasScaleUpTest, IntermixingServers)
{
  vector<string> servers = {"1.2.3.4", "1.2.3.5", "1.2.3.6"};
  vector<string> new_servers = {"1.2.3.4", "1.2.3.7", "1.2.3.5", "1.2.3.8", "1.2.3.6"};
  common_scaling_assertions(servers, new_servers);
}

TEST_F(MemcachedViewElevenVbucketsScaleUpTest, IntermixingServers)
{
  vector<string> servers = {"1.2.3.4", "1.2.3.5", "1.2.3.6"};
  vector<string> new_servers = {"1.2.3.4", "1.2.3.7", "1.2.3.5", "1.2.3.8", "1.2.3.6"};
  common_scaling_assertions(servers, new_servers);
}


TEST_F(MemcachedViewTwentyReplicasScaleDownTest, RemovingMiddleServers)
{
  vector<string> servers = {"1.2.3.4", "1.2.3.5", "1.2.3.6", "1.2.3.7", "1.2.3.8"};
  vector<string> new_servers = {"1.2.3.4", "1.2.3.8"};
  common_scaling_assertions(servers, new_servers);
}

TEST_F(MemcachedViewElevenVbucketsScaleDownTest, RemovingMiddleServers)
{
  vector<string> servers = {"1.2.3.4", "1.2.3.5", "1.2.3.6", "1.2.3.7", "1.2.3.8"};
  vector<string> new_servers = {"1.2.3.4", "1.2.3.8"};
  common_scaling_assertions(servers, new_servers);
}
