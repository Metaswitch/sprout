/**
 * @file impistore_test.cpp UT for Sprout authentication vector store.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */


#include <string>
#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "utils.h"
#include "sas.h"
#include "localstore.h"
#include "astaire_impistore.h"
#include "test_utils.hpp"
#include "test_interposer.hpp"

using namespace std;

/// Constant strings.
static const std::string IMPI = "private@example.com";
static const std::string NONCE1 = "nonce1";
static const std::string NONCE2 = "nonce2";

/// Base fixture for all IMPI store tests.
class AstaireImpiStoreTest : public ::testing::Test
{
public:
  LocalStore* local_store;
  ImpiStore* impi_store;
  AstaireImpiStoreTest()
  {
    local_store = new LocalStore();
    impi_store = new AstaireImpiStore(local_store);;

  }
  virtual ~AstaireImpiStoreTest()
  {
    delete local_store;
    delete impi_store;
  };
};

/// Example IMPI, with a single digest authentication challenge.
ImpiStore::Impi* example_impi_digest()
{
  ImpiStore::Impi* impi = new AstaireImpiStore::Impi(IMPI);
  ImpiStore::AuthChallenge* auth_challenge = new ImpiStore::DigestAuthChallenge(NONCE1, "example.com", "auth", "ha1", time(NULL) + 30);
  auth_challenge->_correlator = "correlator";
  impi->auth_challenges.push_back(auth_challenge);
  return impi;
};

/// Example IMPI, with a single AKA authentication challenge.
ImpiStore::Impi* example_impi_aka()
{
  ImpiStore::Impi* impi = new AstaireImpiStore::Impi(IMPI);
  ImpiStore::AuthChallenge* auth_challenge = new ImpiStore::AKAAuthChallenge(NONCE1, "response", time(NULL) + 30);
  auth_challenge->_correlator = "correlator";
  impi->auth_challenges.push_back(auth_challenge);
  return impi;
};

/// Example IMPI, with both a digest and an AKA authentication challenge.
ImpiStore::Impi* example_impi_digest_aka()
{
  ImpiStore::Impi* impi = new AstaireImpiStore::Impi(IMPI);
  ImpiStore::AuthChallenge* auth_challenge = new ImpiStore::DigestAuthChallenge(NONCE1, "example.com", "auth", "ha1", time(NULL) + 30);
  auth_challenge->_correlator = "correlator";
  impi->auth_challenges.push_back(auth_challenge);
  auth_challenge = new ImpiStore::AKAAuthChallenge(NONCE2, "response", time(NULL) + 30);
  auth_challenge->_correlator = "correlator";
  impi->auth_challenges.push_back(auth_challenge);
  return impi;
};

/// Check that two IMPIs are equal.
void expect_impis_equal(ImpiStore::Impi* impi1, ImpiStore::Impi* impi2)
{
  ASSERT_TRUE(impi1 != NULL);
  ASSERT_TRUE(impi2 != NULL);
  EXPECT_EQ(impi1->impi, impi2->impi);
  EXPECT_EQ(impi1->auth_challenges.size(), impi2->auth_challenges.size());
  for (std::vector<ImpiStore::AuthChallenge*>::iterator it = impi1->auth_challenges.begin();
       it != impi1->auth_challenges.end();
       it++)
  {
    ImpiStore::AuthChallenge* auth_challenge1 = *it;
    ImpiStore::AuthChallenge* auth_challenge2 = impi2->get_auth_challenge(auth_challenge1->_nonce);
    EXPECT_TRUE(auth_challenge2 != NULL);
    if (auth_challenge2 != NULL)
    {
      EXPECT_EQ(auth_challenge1->_type, auth_challenge2->_type);
      EXPECT_EQ(auth_challenge1->_nonce, auth_challenge2->_nonce);
      EXPECT_EQ(auth_challenge1->_nonce_count, auth_challenge2->_nonce_count);
      // Don't check expires.
      EXPECT_EQ(auth_challenge1->_correlator, auth_challenge2->_correlator);
      // Don't check CAS.
      if (auth_challenge1->_type == ImpiStore::AuthChallenge::Type::DIGEST)
      {
        ImpiStore::DigestAuthChallenge* digest_challenge1 = (ImpiStore::DigestAuthChallenge*)auth_challenge1;
        ImpiStore::DigestAuthChallenge* digest_challenge2 = (ImpiStore::DigestAuthChallenge*)auth_challenge2;
        EXPECT_EQ(digest_challenge1->_realm, digest_challenge2->_realm);
        EXPECT_EQ(digest_challenge1->_qop, digest_challenge2->_qop);
        EXPECT_EQ(digest_challenge1->_ha1, digest_challenge2->_ha1);
      }
      else if (auth_challenge1->_type == ImpiStore::AuthChallenge::Type::AKA)
      {
        ImpiStore::AKAAuthChallenge* aka_challenge1 = (ImpiStore::AKAAuthChallenge*)auth_challenge1;
        ImpiStore::AKAAuthChallenge* aka_challenge2 = (ImpiStore::AKAAuthChallenge*)auth_challenge2;
        EXPECT_EQ(aka_challenge1->_response, aka_challenge2->_response);
      }
    }
  }
  for (std::vector<ImpiStore::AuthChallenge*>::iterator it = impi2->auth_challenges.begin();
       it != impi2->auth_challenges.end();
       it++)
  {
    ImpiStore::AuthChallenge* auth_challenge2 = *it;
    ImpiStore::AuthChallenge* auth_challenge1 = impi1->get_auth_challenge(auth_challenge2->_nonce);
    EXPECT_TRUE(auth_challenge1 != NULL);
  }
};

TEST_F(AstaireImpiStoreTest, SetGet)
{
  ImpiStore::Impi* impi1 = example_impi_digest();
  Store::Status status = this->impi_store->set_impi(impi1, 0L);
  ASSERT_EQ(Store::Status::OK, status);
  ImpiStore::Impi* impi2 = this->impi_store->get_impi(IMPI, 0L);
  expect_impis_equal(impi1, impi2);
  delete impi2;
  delete impi1;
}

TEST_F(AstaireImpiStoreTest, SetGetFailure)
{
  ImpiStore::Impi* impi1 = example_impi_digest();
  Store::Status status = this->impi_store->set_impi(impi1, 0L);
  ASSERT_EQ(Store::Status::OK, status);

  this->local_store->force_get_error();
  ImpiStore::Impi* impi2 = this->impi_store->get_impi(IMPI, 0L);
  EXPECT_TRUE(impi2 == NULL);
  delete impi1;
}

TEST_F(AstaireImpiStoreTest, SetDelete)
{
  ImpiStore::Impi* impi1 = example_impi_digest();
  Store::Status status = this->impi_store->set_impi(impi1, 0L);
  ASSERT_EQ(Store::Status::OK, status);
  status = this->impi_store->delete_impi(impi1, 0L);
  ASSERT_EQ(Store::Status::OK, status);
  delete impi1;
}

TEST_F(AstaireImpiStoreTest, IMPICorruptJSON)
{
  local_store->set_data("impi", IMPI, "{]", 0, 30, 0L);
  ImpiStore::Impi* impi = impi_store->get_impi(IMPI, 0L);
  ASSERT_TRUE(impi != NULL);
  EXPECT_TRUE(impi->auth_challenges.empty());
  delete impi;
}

TEST_F(AstaireImpiStoreTest, IMPINotObject)
{
  local_store->set_data("impi", IMPI, "\"not an object\"", 0, 30, 0L);
  ImpiStore::Impi* impi = impi_store->get_impi(IMPI, 0L);
  ASSERT_TRUE(impi != NULL);
  EXPECT_TRUE(impi->auth_challenges.empty());
  delete impi;
}

TEST_F(AstaireImpiStoreTest, ChallengeNotObject)
{
  local_store->set_data("impi", IMPI, "{\"authChallenges\":[\"not an object\"]}", 0, 30, 0L);
  ImpiStore::Impi* impi = impi_store->get_impi(IMPI, 0L);
  ASSERT_TRUE(impi != NULL);
  EXPECT_EQ(0, impi->auth_challenges.size());
  delete impi;
}

TEST_F(AstaireImpiStoreTest, ChallengeDigest)
{
  local_store->set_data("impi", IMPI, "{\"authChallenges\":[{\"type\":\"digest\",\"nonce\":\"nonce\",\"realm\":\"example.com\",\"qop\":\"auth\",\"ha1\":\"ha1\"}]}", 0, 30, 0L);
  ImpiStore::Impi* impi = impi_store->get_impi(IMPI, 0L);
  ASSERT_TRUE(impi != NULL);
  ASSERT_EQ(1, impi->auth_challenges.size());
  ASSERT_EQ(ImpiStore::AuthChallenge::Type::DIGEST, impi->auth_challenges[0]->_type);
  delete impi;
}

TEST_F(AstaireImpiStoreTest, ChallengeUnknownType)
{
  local_store->set_data("impi", IMPI, "{\"authChallenges\":[{\"type\":\"unknown\"}]}", 0, 30, 0L);
  ImpiStore::Impi* impi = impi_store->get_impi(IMPI, 0L);
  ASSERT_TRUE(impi != NULL);
  EXPECT_EQ(0, impi->auth_challenges.size());
  delete impi;
}

TEST_F(AstaireImpiStoreTest, ChallengeDigestMissingRealm)
{
  local_store->set_data("impi", IMPI, "{\"authChallenges\":[{\"type\":\"digest\",\"nonce\":\"nonce\",\"qop\":\"auth\",\"ha1\":\"ha1\"}]}", 0, 30, 0L);
  ImpiStore::Impi* impi = impi_store->get_impi(IMPI, 0L);
  ASSERT_TRUE(impi != NULL);
  EXPECT_EQ(0, impi->auth_challenges.size());
  delete impi;
}

TEST_F(AstaireImpiStoreTest, ChallengeDigestMissingQoP)
{
  local_store->set_data("impi", IMPI, "{\"authChallenges\":[{\"type\":\"digest\",\"nonce\":\"nonce\",\"realm\":\"example.com\",\"ha1\":\"ha1\"}]}", 0, 30, 0L);
  ImpiStore::Impi* impi = impi_store->get_impi(IMPI, 0L);
  ASSERT_TRUE(impi != NULL);
  EXPECT_EQ(0, impi->auth_challenges.size());
  delete impi;
}

TEST_F(AstaireImpiStoreTest, ChallengeDigestMissingHA1)
{
  local_store->set_data("impi", IMPI, "{\"authChallenges\":[{\"type\":\"digest\",\"nonce\":\"nonce\",\"realm\":\"example.com\",\"qop\":\"auth\"}]}", 0, 30, 0L);
  ImpiStore::Impi* impi = impi_store->get_impi(IMPI, 0L);
  ASSERT_TRUE(impi != NULL);
  EXPECT_EQ(0, impi->auth_challenges.size());
  delete impi;
}

TEST_F(AstaireImpiStoreTest, ChallengeDigestMissingNonce)
{
  local_store->set_data("impi", IMPI, "{\"authChallenges\":[{\"type\":\"digest\",\"realm\":\"example.com\",\"qop\":\"auth\",\"ha1\":\"ha1\"}]}", 0, 30, 0L);
  ImpiStore::Impi* impi = impi_store->get_impi(IMPI, 0L);
  ASSERT_TRUE(impi != NULL);
  EXPECT_EQ(0, impi->auth_challenges.size());
  delete impi;
}

TEST_F(AstaireImpiStoreTest, ChallengeDigestExpiresInPast)
{
  local_store->set_data("impi", IMPI, "{\"authChallenges\":[{\"type\":\"digest\",\"nonce\":\"nonce\",\"realm\":\"example.com\",\"qop\":\"auth\",\"ha1\":\"ha1\",\"expires\":1}]}", 0, 30, 0L);
  ImpiStore::Impi* impi = impi_store->get_impi(IMPI, 0L);
  ASSERT_TRUE(impi != NULL);
  EXPECT_EQ(0, impi->auth_challenges.size());
  delete impi;
}

TEST_F(AstaireImpiStoreTest, ChallengeAKAMissingResponse)
{
  local_store->set_data("impi", IMPI, "{\"authChallenges\":[{\"type\":\"aka\",\"nonce\":\"nonce\"}]}", 0, 30, 0L);
  ImpiStore::Impi* impi = impi_store->get_impi(IMPI, 0L);
  ASSERT_TRUE(impi != NULL);
  EXPECT_EQ(0, impi->auth_challenges.size());
  delete impi;
}
