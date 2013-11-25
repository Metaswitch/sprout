

/// Generic class for holding Authentication Vectors.
class AuthVector
{
public:
  typedef enum {SIP_DIGEST, DIGEST_AKAv1_MD5} Scheme;

  Scheme scheme() { return _scheme; };

private:
  Scheme _scheme;
}


/// Digest Authentication Vector
class AuthVectorDigest : public AuthVector;
{
public:
  AuthVectorDigest(std::string realm,
                   std::string qop,
                   std::string ha1) :
    _scheme(SIP_DIGEST),
    _realm(realm)
    _qop(qop),
    _ha1(ha1)
  {
  }

  ~AuthVectorDigest()
  {
  }

  const std::string& realm() { return _realm; };
  const std::string& qop() { return _qop; };
  const std::string& ha1() { return _ha1; };

private:
  std::string _realm;
  std::string _qop;
  std::string _ha1;
}


/// AKA Authentication Vector
class AuthVectorAKA
{
public:
  AuthVectorAKA(std::string challenge,
                std::string response) :
    _scheme(DIGEST_AKAv1_MD5),
    _challenge(challenge),
    _response(response)
  {
  }

  ~AuthVector()
  {
  }

  const std::string& challenge() { return _challenge; };
  const std::string& response() { return _response; };

private:
  std::string _challenge;
  std::string _response;
};

class AvStore
{
public:
  AvStore();
  ~AvStore();

  void set_av(const std::string& impi,
              const std::string& nonce,
              AuthVector* av);

  AuthVector* get_av(const std::string& impi,
                     const std::string& nonce);

private:
  pthread_mutex_lock* _av_map_lock;
  std::map<std::string, std::string> _av_map;
}
