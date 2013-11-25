

#include <map>
#include <ostringstream>
#include <istringstream>

#include "avstore.h"


AvStore::AvStore() :
  _av_map_lock(PTHREAD_MUTEX_INITIALIZER),
  _av_map()
{
}

AvStore::~AvStore()
{
}

void AvStore::set_av(const std::string& impi,
                     const std::string& nonce,
                     AuthVector* av)
{
  std::string key = impi + '\0' + nonce;
  std::string data = serialize_av(av);

  pthread_mutex_lock(&_av_map_lock);
  _av_map[key] = data;
  pthread_mutex_unlock(&_av_map_lock);
}

AuthVector* AvStore::get_av(const std::string& impi,
                            const std::string& nonce)
{
  AuthVector* av = NULL;
  std::string key = impi + '\0' + nonce;

  pthread_mutex_lock(&_av_map_lock);
  std::map<std::string, std::string>::const_iterator i = _av_map.find(key);
  if (i != _av_map.end())
  {
    av = deserialize_av(i->second);
  }
  pthread_mutex_unlock(&_av_map_lock);

  return av;
}

/// Serialize the contents of an AuthVector
std::string AvStore::serialize_av(AuthVector* av)
{
  std::ostringstream oss(std::ostringstream::out|std::ostringstream::binary);

  AuthVector::Scheme scheme = av->scheme();
  oss.write((const char*)&scheme, sizeof(AuthVector::Scheme));

  if (scheme == SIP_DIGEST)
  {
    oss << av->realm() << '\0';
    oss << av->qop() << '\0';
    oss << av->ha1() << '\0';
  }
  else if (scheme == DIGEST_AKAv1_MD5)
  {
    oss << av->challenge() << '\0';
    oss << av->response() << '\0';
  }

  return oss.str();
}


/// Deserialize the contents of an AuthVector
AuthVector* AvStore::deserialize_av(const std::string& s)
{
  AuthVector* av = NULL;

  std::istringstream iss(s, std::istringstream::in|std::istringstream::binary);

  AuthVector::Scheme scheme;
  iss.read((char *)&scheme, sizeof(AuthVector::Scheme));

  if (scheme == SIP_DIGEST)
  {
    std::string realm;
    std::string qop;
    std::string ha1;
    getline(iss, realm, '\0');
    getline(iss, qop, '\0');
    getline(iss, ha1, '\0');
    av = (AuthVector*)new AuthVectorDigest(realm, qop, ha1);
  }
  else if (scheme == DIGEST_AKAv1_MD5)
  {
    std::string challenge;
    std::string response;
    getline(iss, challenge, '\0');
    getline(iss, response, '\0');
    av = (AuthVector*)new AuthVectorAKA(challenge, response);
  }

  return av;
}

