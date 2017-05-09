/**
 * @file impistore_test.cpp UT for Sprout authentication vector store.
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2013  Metaswitch Networks Ltd
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

#include "utils.h"
#include "sas.h"
#include "localstore.h"
#include "impistore.h"
#include "test_utils.hpp"
#include "test_interposer.hpp"

using namespace std;

/// Wrapper around IMPI store implementations, to allow them to be swapped in
/// and out of different test fixtures.
class ImpiStoreImpl
{
public:
  virtual ~ImpiStoreImpl() {};
  virtual Store::Status set_impi(ImpiStore::Impi* impi) = 0;
  virtual ImpiStore::Impi* get_impi(const std::string& impi) = 0;
  virtual ImpiStore::Impi* get_impi_with_nonce(const std::string& impi, const std::string& nonce) = 0;
  virtual Store::Status delete_impi(ImpiStore::Impi* impi) = 0;
};

class LiveImpiStoreImpl : public ImpiStoreImpl
{
public:
  LiveImpiStoreImpl(ImpiStore* store) : _store(store) {};
  virtual ~LiveImpiStoreImpl() {delete _store;};
  virtual Store::Status set_impi(ImpiStore::Impi* impi)
  {
    return _store->set_impi(impi, 0L);
  };
  virtual ImpiStore::Impi* get_impi(const std::string& impi)
  {
    return _store->get_impi(impi, 0L);
  };
  virtual ImpiStore::Impi* get_impi_with_nonce(const std::string& impi, const std::string& nonce)
  {
    return _store->get_impi_with_nonce(impi, nonce, 0L);
  };
  virtual Store::Status delete_impi(ImpiStore::Impi* impi)
  {
    return _store->delete_impi(impi, 0L);
  };
private:
  ImpiStore* _store;
};

class LiveImpiStoreImplImpi : public LiveImpiStoreImpl
{
public:
  LiveImpiStoreImplImpi(Store* store) : LiveImpiStoreImpl(new ImpiStore(store, ImpiStore::Mode::READ_IMPI_WRITE_IMPI)) {};
};

class LiveImpiStoreImplAvImpi : public LiveImpiStoreImpl
{
public:
  LiveImpiStoreImplAvImpi(Store* store) : LiveImpiStoreImpl(new ImpiStore(store, ImpiStore::Mode::READ_AV_IMPI_WRITE_AV_IMPI)) {};
};

class LiveImpiStoreImplAvLostImpi : public LiveImpiStoreImplAvImpi
{
public:
  LiveImpiStoreImplAvLostImpi(Store* store) : LiveImpiStoreImplAvImpi(store), _store(store) {};
  virtual Store::Status set_impi(ImpiStore::Impi* impi)
  {
    Store::Status status = LiveImpiStoreImplAvImpi::set_impi(impi);
    (void)_store->delete_data("impi", impi->impi, 0L);
    return status;
  };
private:
  Store* _store;
};


/// Base fixture for all IMPI store tests.
class ImpiStoreTest : public ::testing::Test
{
public:
  LocalStore* local_store;
  ImpiStoreTest() :
    local_store(new LocalStore()) {};
  virtual ~ImpiStoreTest()
  {
    delete local_store;
  };
};

/// Constant strings.
static const std::string IMPI = "private@example.com";
static const std::string NONCE1 = "nonce1";
static const std::string NONCE2 = "nonce2";

/// Example IMPI, with a single digest authentication challenge.
ImpiStore::Impi* example_impi_digest()
{
  ImpiStore::Impi* impi = new ImpiStore::Impi(IMPI);
  ImpiStore::AuthChallenge* auth_challenge = new ImpiStore::DigestAuthChallenge(NONCE1, "example.com", "auth", "ha1", time(NULL) + 30);
  auth_challenge->correlator = "correlator";
  impi->auth_challenges.push_back(auth_challenge);
  return impi;
};

/// Example IMPI, with a single AKA authentication challenge.
ImpiStore::Impi* example_impi_aka()
{
  ImpiStore::Impi* impi = new ImpiStore::Impi(IMPI);
  ImpiStore::AuthChallenge* auth_challenge = new ImpiStore::AKAAuthChallenge(NONCE1, "response", time(NULL) + 30);
  auth_challenge->correlator = "correlator";
  impi->auth_challenges.push_back(auth_challenge);
  return impi;
};

/// Example IMPI, with both a digest and an AKA authentication challenge.
ImpiStore::Impi* example_impi_digest_aka()
{
  ImpiStore::Impi* impi = new ImpiStore::Impi(IMPI);
  ImpiStore::AuthChallenge* auth_challenge = new ImpiStore::DigestAuthChallenge(NONCE1, "example.com", "auth", "ha1", time(NULL) + 30);
  auth_challenge->correlator = "correlator";
  impi->auth_challenges.push_back(auth_challenge);
  auth_challenge = new ImpiStore::AKAAuthChallenge(NONCE2, "response", time(NULL) + 30);
  auth_challenge->correlator = "correlator";
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
    ImpiStore::AuthChallenge* auth_challenge2 = impi2->get_auth_challenge(auth_challenge1->nonce);
    EXPECT_TRUE(auth_challenge2 != NULL);
    if (auth_challenge2 != NULL)
    {
      EXPECT_EQ(auth_challenge1->type, auth_challenge2->type);
      EXPECT_EQ(auth_challenge1->nonce, auth_challenge2->nonce);
      EXPECT_EQ(auth_challenge1->nonce_count, auth_challenge2->nonce_count);
      // Don't check expires.
      EXPECT_EQ(auth_challenge1->correlator, auth_challenge2->correlator);
      // Don't check CAS.
      if (auth_challenge1->type == ImpiStore::AuthChallenge::Type::DIGEST)
      {
        ImpiStore::DigestAuthChallenge* digest_challenge1 = (ImpiStore::DigestAuthChallenge*)auth_challenge1;
        ImpiStore::DigestAuthChallenge* digest_challenge2 = (ImpiStore::DigestAuthChallenge*)auth_challenge2;
        EXPECT_EQ(digest_challenge1->realm, digest_challenge2->realm);
        EXPECT_EQ(digest_challenge1->qop, digest_challenge2->qop);
        EXPECT_EQ(digest_challenge1->ha1, digest_challenge2->ha1);
      }
      else if (auth_challenge1->type == ImpiStore::AuthChallenge::Type::AKA)
      {
        ImpiStore::AKAAuthChallenge* aka_challenge1 = (ImpiStore::AKAAuthChallenge*)auth_challenge1;
        ImpiStore::AKAAuthChallenge* aka_challenge2 = (ImpiStore::AKAAuthChallenge*)auth_challenge2;
        EXPECT_EQ(aka_challenge1->response, aka_challenge2->response);
      }
    }
  }
  for (std::vector<ImpiStore::AuthChallenge*>::iterator it = impi2->auth_challenges.begin();
       it != impi2->auth_challenges.end();
       it++)
  {
    ImpiStore::AuthChallenge* auth_challenge2 = *it;
    ImpiStore::AuthChallenge* auth_challenge1 = impi1->get_auth_challenge(auth_challenge2->nonce);
    EXPECT_TRUE(auth_challenge1 != NULL);
  }
};

/// Fixture for ImpiOneStoreTest.
///
/// The fixture is a template, parameterized over the different IMPI store
/// implementations.
///
/// These tests test the behavior of a single store.
template<class T> class ImpiOneStoreTest : public ImpiStoreTest
{
public:
  ImpiStoreImpl* impi_store;
  ImpiOneStoreTest() :
    ImpiStoreTest(),
    impi_store(new T(local_store))
     {};
  virtual ~ImpiOneStoreTest()
  {
    delete impi_store;
  };
};

typedef ::testing::Types<
  LiveImpiStoreImplAvImpi,
  LiveImpiStoreImplImpi
> OneStoreScenarios;

TYPED_TEST_CASE(ImpiOneStoreTest, OneStoreScenarios);

TYPED_TEST(ImpiOneStoreTest, SetGet)
{
  ImpiStore::Impi* impi1 = example_impi_digest();
  Store::Status status = this->impi_store->set_impi(impi1);
  ASSERT_EQ(Store::Status::OK, status);
  ImpiStore::Impi* impi2 = this->impi_store->get_impi(IMPI);
  expect_impis_equal(impi1, impi2);
  delete impi2;
  delete impi1;
}

TYPED_TEST(ImpiOneStoreTest, SetGetWithNonce)
{
  ImpiStore::Impi* impi1 = example_impi_digest();
  Store::Status status = this->impi_store->set_impi(impi1);
  ASSERT_EQ(Store::Status::OK, status);
  ImpiStore::Impi* impi2 = this->impi_store->get_impi_with_nonce(IMPI, NONCE1);
  expect_impis_equal(impi1, impi2);
  delete impi2;
  delete impi1;
}

TYPED_TEST(ImpiOneStoreTest, SetGetFailure)
{
  ImpiStore::Impi* impi1 = example_impi_digest();
  Store::Status status = this->impi_store->set_impi(impi1);
  ASSERT_EQ(Store::Status::OK, status);

  this->local_store->force_get_error();
  ImpiStore::Impi* impi2 = this->impi_store->get_impi(IMPI);
  EXPECT_TRUE(impi2 == NULL);
  delete impi1;
}

/// Wrapper class for scenarios that involve 2 different IMPI store
/// implementations.
class TwoStoreScenario
{
public:
  TwoStoreScenario(ImpiStoreImpl* _store1, ImpiStoreImpl* _store2) : store1(_store1), store2(_store2) {};
  ~TwoStoreScenario() {delete store1; delete store2;};
  ImpiStoreImpl* store1;
  ImpiStoreImpl* store2;
};

/// Fixture for ImpiTwoStoreTest.
///
/// The fixture is a template, parameterized over the different IMPI store
/// implementations.
///
/// These tests test interactions before different IMPI store implementations,
/// ensuring that they can read and write to a shared store.
template<class T> class ImpiTwoStoreBaseTest : public ImpiStoreTest
{
public:
  TwoStoreScenario* scenario;
  ImpiTwoStoreBaseTest() :
    ImpiStoreTest(),
    scenario(new T(local_store))
     {};
  virtual ~ImpiTwoStoreBaseTest()
  {
    delete scenario;
  };
};

template<class T1, class T2>
class TwoStoreScenarioTemplate : public TwoStoreScenario
{
public:
  TwoStoreScenarioTemplate(Store* store) : TwoStoreScenario(new T1(store), new T2(store)) {};
};

template<class T> class ImpiTwoStoreTest : public ImpiTwoStoreBaseTest<T> {};

typedef ::testing::Types<
  TwoStoreScenarioTemplate<LiveImpiStoreImplAvImpi, LiveImpiStoreImplAvImpi>,
  TwoStoreScenarioTemplate<LiveImpiStoreImplAvImpi, LiveImpiStoreImplImpi>,
  TwoStoreScenarioTemplate<LiveImpiStoreImplImpi, LiveImpiStoreImplAvImpi>,
  TwoStoreScenarioTemplate<LiveImpiStoreImplImpi, LiveImpiStoreImplImpi>
> TwoStoreScenarios;

TYPED_TEST_CASE(ImpiTwoStoreTest, TwoStoreScenarios);

TYPED_TEST(ImpiTwoStoreTest, Set1Get2)
{
  ImpiStore::Impi* impi1 = example_impi_digest();
  Store::Status status = this->scenario->store1->set_impi(impi1);
  ASSERT_EQ(Store::Status::OK, status);
  ImpiStore::Impi* impi2 = this->scenario->store2->get_impi(IMPI);
  expect_impis_equal(impi1, impi2);
  delete impi2;
  delete impi1;
}

TYPED_TEST(ImpiTwoStoreTest, Set1DeleteAC1Get2)
{
  ImpiStore::Impi* impi1 = example_impi_digest_aka();
  Store::Status status = this->scenario->store1->set_impi(impi1);
  ASSERT_EQ(Store::Status::OK, status);
  ImpiStore::Impi* impi2 = this->scenario->store1->get_impi(IMPI);
  ASSERT_TRUE(impi2 != NULL);
  expect_impis_equal(impi1, impi2);
  ASSERT_EQ(2, impi2->auth_challenges.size());
  delete impi2->auth_challenges[1];
  impi2->auth_challenges.erase(impi2->auth_challenges.begin() + 1);
  status = this->scenario->store1->set_impi(impi2);
  ASSERT_EQ(Store::Status::OK, status);
  ImpiStore::Impi* impi3 = this->scenario->store2->get_impi(IMPI);
  expect_impis_equal(impi2, impi3);
  delete impi3;
  delete impi2;
  delete impi1;
}

TYPED_TEST(ImpiTwoStoreTest, Set1DeleteAC1GetNonce2)
{
  ImpiStore::Impi* impi1 = example_impi_digest_aka();
  Store::Status status = this->scenario->store1->set_impi(impi1);
  ASSERT_EQ(Store::Status::OK, status);
  ImpiStore::Impi* impi2 = this->scenario->store1->get_impi(IMPI);
  ASSERT_TRUE(impi2 != NULL);
  expect_impis_equal(impi1, impi2);
  ASSERT_EQ(2, impi2->auth_challenges.size());
  delete impi2->auth_challenges[1];
  impi2->auth_challenges.erase(impi2->auth_challenges.begin() + 1);
  status = this->scenario->store1->set_impi(impi2);
  ASSERT_EQ(Store::Status::OK, status);
  ImpiStore::Impi* impi3 = this->scenario->store2->get_impi_with_nonce(IMPI, NONCE1);
  expect_impis_equal(impi2, impi3);
  delete impi3;
  delete impi2;
  delete impi1;
}

TYPED_TEST(ImpiTwoStoreTest, Set1DeleteAC2GetNonce1)
{
  ImpiStore::Impi* impi1 = example_impi_digest_aka();
  Store::Status status = this->scenario->store1->set_impi(impi1);
  ASSERT_EQ(Store::Status::OK, status);
  ImpiStore::Impi* impi2 = this->scenario->store2->get_impi(IMPI);
  ASSERT_TRUE(impi2 != NULL);
  ASSERT_EQ(2, impi2->auth_challenges.size());
  delete impi2->auth_challenges[1];
  impi2->auth_challenges.erase(impi2->auth_challenges.begin() + 1);
  status = this->scenario->store2->set_impi(impi2);
  ASSERT_EQ(Store::Status::OK, status);
  ImpiStore::Impi* impi3 = this->scenario->store1->get_impi_with_nonce(IMPI, NONCE1);
  expect_impis_equal(impi2, impi3);
  delete impi3;
  delete impi2;
  delete impi1;
}

TYPED_TEST(ImpiTwoStoreTest, Write1Delete1Read2)
{
  ImpiStore::Impi* impi1 = example_impi_digest();
  Store::Status status = this->scenario->store1->set_impi(impi1);
  ASSERT_EQ(Store::Status::OK, status);
  ImpiStore::Impi* impi2 = this->scenario->store1->get_impi(IMPI);
  ASSERT_TRUE(impi2 != NULL);
  status = this->scenario->store1->delete_impi(impi2);
  ASSERT_EQ(Store::Status::OK, status);
  ImpiStore::Impi* impi3 = this->scenario->store2->get_impi(IMPI);
  ASSERT_TRUE(impi3 != NULL);
  EXPECT_TRUE(impi3->auth_challenges.empty());
  delete impi3;
  delete impi2;
  delete impi1;
}


/// Fixture for ImpiTwoStoreLostImpiTest.
///
/// These tests are similar to ImpiTwoStoreTest, except that they test FT
/// scenarios that even work when the IMPI record is lost.
template<class T> class ImpiTwoStoreLostImpiTest : public ImpiTwoStoreBaseTest<T> {};

typedef ::testing::Types<
  TwoStoreScenarioTemplate<LiveImpiStoreImplAvImpi, LiveImpiStoreImplAvImpi>,
  TwoStoreScenarioTemplate<LiveImpiStoreImplAvImpi, LiveImpiStoreImplImpi>,
  TwoStoreScenarioTemplate<LiveImpiStoreImplImpi, LiveImpiStoreImplAvImpi>,
  TwoStoreScenarioTemplate<LiveImpiStoreImplImpi, LiveImpiStoreImplImpi>,
  TwoStoreScenarioTemplate<LiveImpiStoreImplAvLostImpi, LiveImpiStoreImplAvImpi>
> TwoStoreLostImpiScenarios;

TYPED_TEST_CASE(ImpiTwoStoreLostImpiTest, TwoStoreLostImpiScenarios);

TYPED_TEST(ImpiTwoStoreLostImpiTest, Set1GetNonce2)
{
  ImpiStore::Impi* impi1 = example_impi_digest();
  Store::Status status = this->scenario->store1->set_impi(impi1);
  ASSERT_EQ(Store::Status::OK, status);
  ImpiStore::Impi* impi2 = this->scenario->store2->get_impi_with_nonce(IMPI, NONCE1);
  expect_impis_equal(impi1, impi2);
  delete impi2;
  delete impi1;
}

TYPED_TEST(ImpiTwoStoreLostImpiTest, Write1Delete1Read2)
{
  ImpiStore::Impi* impi1 = example_impi_digest();
  Store::Status status = this->scenario->store1->set_impi(impi1);
  ASSERT_EQ(Store::Status::OK, status);
  ImpiStore::Impi* impi2 = this->scenario->store1->get_impi_with_nonce(IMPI, NONCE1);
  ASSERT_TRUE(impi2 != NULL);
  status = this->scenario->store1->delete_impi(impi2);
  ASSERT_EQ(Store::Status::OK, status);
  ImpiStore::Impi* impi3 = this->scenario->store2->get_impi_with_nonce(IMPI, NONCE1);
  ASSERT_TRUE(impi3 != NULL);
  EXPECT_TRUE(impi3->auth_challenges.empty());
  delete impi3;
  delete impi2;
  delete impi1;
}

TYPED_TEST(ImpiTwoStoreLostImpiTest, Write1ReadNonce2Write2ReadNonce1)
{
  ImpiStore::Impi* impi1 = example_impi_digest();
  Store::Status status = this->scenario->store1->set_impi(impi1);
  ASSERT_EQ(Store::Status::OK, status);
  ImpiStore::Impi* impi2 = this->scenario->store2->get_impi_with_nonce(IMPI, NONCE1);
  expect_impis_equal(impi1, impi2);
  ASSERT_TRUE(impi2 != NULL);
  status = this->scenario->store2->set_impi(impi2);
  ASSERT_EQ(Store::Status::OK, status);
  ImpiStore::Impi* impi3 = this->scenario->store1->get_impi_with_nonce(IMPI, NONCE1);
  expect_impis_equal(impi1, impi3);
  delete impi3;
  delete impi2;
  delete impi1;
}

TYPED_TEST(ImpiTwoStoreLostImpiTest, Contention)
{
  // Set an IMPI.
  ImpiStore::Impi* impi1 = example_impi_digest();
  Store::Status status = this->scenario->store1->set_impi(impi1);
  ASSERT_EQ(Store::Status::OK, status);
  // Read it back via both stores.
  ImpiStore::Impi* impi2 = this->scenario->store1->get_impi_with_nonce(IMPI, NONCE1);
  ASSERT_TRUE(impi2 != NULL);
  ImpiStore::Impi* impi3 = this->scenario->store2->get_impi_with_nonce(IMPI, NONCE1);
  ASSERT_TRUE(impi3 != NULL);
  // Update and write back via the 1st store.
  impi2->auth_challenges[0]->correlator = "conflict";
  status = this->scenario->store1->set_impi(impi2);
  ASSERT_EQ(Store::Status::OK, status);
  // Now try and update and write back via the 2nd store - fail with contention.
  impi3->auth_challenges[0]->correlator = "other conflict";
  status = this->scenario->store2->set_impi(impi3);
  ASSERT_EQ(Store::Status::DATA_CONTENTION, status);
  // Now re-read it via the second store, and successfully make the update.
  delete impi3;
  impi3 = this->scenario->store2->get_impi_with_nonce(IMPI, NONCE1);
  ASSERT_TRUE(impi3 != NULL);
  impi3->auth_challenges[0]->correlator = "other conflict";
  status = this->scenario->store2->set_impi(impi3);
  ASSERT_EQ(Store::Status::OK, status);
  delete impi3;
  delete impi2;
  delete impi1;
}


/// Fixture for ImpiStoreParsingTest.
///
/// These tests cover parsing of data from JSON.
class ImpiStoreParsingTest : public ImpiStoreTest
{
public:
  ImpiStore* impi_store;
  ImpiStoreParsingTest() :
    ImpiStoreTest(),
    impi_store(new ImpiStore(local_store, ImpiStore::Mode::READ_AV_IMPI_WRITE_AV_IMPI))
  {};
  virtual ~ImpiStoreParsingTest()
  {
    delete impi_store;
  };
};

TEST_F(ImpiStoreParsingTest, IMPICorruptJSON)
{
  local_store->set_data("impi", IMPI, "{]", 0, 30, 0L);
  ImpiStore::Impi* impi = impi_store->get_impi(IMPI, 0L);
  ASSERT_TRUE(impi != NULL);
  EXPECT_TRUE(impi->auth_challenges.empty());
  delete impi;
}

TEST_F(ImpiStoreParsingTest, IMPINotObject)
{
  local_store->set_data("impi", IMPI, "\"not an object\"", 0, 30, 0L);
  ImpiStore::Impi* impi = impi_store->get_impi(IMPI, 0L);
  ASSERT_TRUE(impi != NULL);
  EXPECT_TRUE(impi->auth_challenges.empty());
  delete impi;
}

TEST_F(ImpiStoreParsingTest, ChallengeNotObject)
{
  local_store->set_data("impi", IMPI, "{\"authChallenges\":[\"not an object\"]}", 0, 30, 0L);
  ImpiStore::Impi* impi = impi_store->get_impi(IMPI, 0L);
  ASSERT_TRUE(impi != NULL);
  EXPECT_EQ(0, impi->auth_challenges.size());
  delete impi;
}

TEST_F(ImpiStoreParsingTest, ChallengeDigest)
{
  local_store->set_data("impi", IMPI, "{\"authChallenges\":[{\"type\":\"digest\",\"nonce\":\"nonce\",\"realm\":\"example.com\",\"qop\":\"auth\",\"ha1\":\"ha1\"}]}", 0, 30, 0L);
  ImpiStore::Impi* impi = impi_store->get_impi(IMPI, 0L);
  ASSERT_TRUE(impi != NULL);
  ASSERT_EQ(1, impi->auth_challenges.size());
  ASSERT_EQ(ImpiStore::AuthChallenge::Type::DIGEST, impi->auth_challenges[0]->type);
  delete impi;
}

TEST_F(ImpiStoreParsingTest, ChallengeUnknownType)
{
  local_store->set_data("impi", IMPI, "{\"authChallenges\":[{\"type\":\"unknown\"}]}", 0, 30, 0L);
  ImpiStore::Impi* impi = impi_store->get_impi(IMPI, 0L);
  ASSERT_TRUE(impi != NULL);
  EXPECT_EQ(0, impi->auth_challenges.size());
  delete impi;
}

TEST_F(ImpiStoreParsingTest, ChallengeDigestMissingRealm)
{
  local_store->set_data("impi", IMPI, "{\"authChallenges\":[{\"type\":\"digest\",\"nonce\":\"nonce\",\"qop\":\"auth\",\"ha1\":\"ha1\"}]}", 0, 30, 0L);
  ImpiStore::Impi* impi = impi_store->get_impi(IMPI, 0L);
  ASSERT_TRUE(impi != NULL);
  EXPECT_EQ(0, impi->auth_challenges.size());
  delete impi;
}

TEST_F(ImpiStoreParsingTest, ChallengeDigestMissingQoP)
{
  local_store->set_data("impi", IMPI, "{\"authChallenges\":[{\"type\":\"digest\",\"nonce\":\"nonce\",\"realm\":\"example.com\",\"ha1\":\"ha1\"}]}", 0, 30, 0L);
  ImpiStore::Impi* impi = impi_store->get_impi(IMPI, 0L);
  ASSERT_TRUE(impi != NULL);
  EXPECT_EQ(0, impi->auth_challenges.size());
  delete impi;
}

TEST_F(ImpiStoreParsingTest, ChallengeDigestMissingHA1)
{
  local_store->set_data("impi", IMPI, "{\"authChallenges\":[{\"type\":\"digest\",\"nonce\":\"nonce\",\"realm\":\"example.com\",\"qop\":\"auth\"}]}", 0, 30, 0L);
  ImpiStore::Impi* impi = impi_store->get_impi(IMPI, 0L);
  ASSERT_TRUE(impi != NULL);
  EXPECT_EQ(0, impi->auth_challenges.size());
  delete impi;
}

TEST_F(ImpiStoreParsingTest, ChallengeDigestMissingNonce)
{
  local_store->set_data("impi", IMPI, "{\"authChallenges\":[{\"type\":\"digest\",\"realm\":\"example.com\",\"qop\":\"auth\",\"ha1\":\"ha1\"}]}", 0, 30, 0L);
  ImpiStore::Impi* impi = impi_store->get_impi(IMPI, 0L);
  ASSERT_TRUE(impi != NULL);
  EXPECT_EQ(0, impi->auth_challenges.size());
  delete impi;
}

TEST_F(ImpiStoreParsingTest, ChallengeDigestExpiresInPast)
{
  local_store->set_data("impi", IMPI, "{\"authChallenges\":[{\"type\":\"digest\",\"nonce\":\"nonce\",\"realm\":\"example.com\",\"qop\":\"auth\",\"ha1\":\"ha1\",\"expires\":1}]}", 0, 30, 0L);
  ImpiStore::Impi* impi = impi_store->get_impi(IMPI, 0L);
  ASSERT_TRUE(impi != NULL);
  EXPECT_EQ(0, impi->auth_challenges.size());
  delete impi;
}

TEST_F(ImpiStoreParsingTest, ChallengeAKAMissingResponse)
{
  local_store->set_data("impi", IMPI, "{\"authChallenges\":[{\"type\":\"aka\",\"nonce\":\"nonce\"}]}", 0, 30, 0L);
  ImpiStore::Impi* impi = impi_store->get_impi(IMPI, 0L);
  ASSERT_TRUE(impi != NULL);
  EXPECT_EQ(0, impi->auth_challenges.size());
  delete impi;
}

TEST_F(ImpiStoreParsingTest, AVCorruptJSON)
{
  local_store->set_data("av", IMPI + '\\' + NONCE1, "{]", 0, 30, 0L);
  ImpiStore::Impi* impi = impi_store->get_impi_with_nonce(IMPI, NONCE1, 0L);
  ASSERT_TRUE(impi != NULL);
  EXPECT_TRUE(impi->auth_challenges.empty());
  delete impi;
}

TEST_F(ImpiStoreParsingTest, AVNotObject)
{
  local_store->set_data("av", IMPI + '\\' + NONCE1, "\"not an object\"", 0, 30, 0L);
  ImpiStore::Impi* impi = impi_store->get_impi_with_nonce(IMPI, NONCE1, 0L);
  ASSERT_TRUE(impi != NULL);
  EXPECT_TRUE(impi->auth_challenges.empty());
  delete impi;
}

TEST_F(ImpiStoreParsingTest, AVDigest)
{
  local_store->set_data("av", IMPI + '\\' + NONCE1, "{\"digest\":{\"realm\":\"example.com\",\"qop\":\"auth\",\"ha1\":\"ha1\"}}", 0, 30, 0L);
  ImpiStore::Impi* impi = impi_store->get_impi_with_nonce(IMPI, NONCE1, 0L);
  ASSERT_TRUE(impi != NULL);
  ASSERT_EQ(1, impi->auth_challenges.size());
  ASSERT_EQ(ImpiStore::AuthChallenge::Type::DIGEST, impi->auth_challenges[0]->type);
  delete impi;
}

TEST_F(ImpiStoreParsingTest, AVAKA)
{
  local_store->set_data("av", IMPI + '\\' + NONCE1, "{\"aka\":{\"response\":\"response\"}}", 0, 30, 0L);
  ImpiStore::Impi* impi = impi_store->get_impi_with_nonce(IMPI, NONCE1, 0L);
  ASSERT_TRUE(impi != NULL);
  ASSERT_EQ(1, impi->auth_challenges.size());
  ASSERT_EQ(ImpiStore::AuthChallenge::Type::AKA, impi->auth_challenges[0]->type);
  delete impi;
}

TEST_F(ImpiStoreParsingTest, AVDigestAndAKA)
{
  local_store->set_data("av", IMPI + '\\' + NONCE1, "{\"digest\":{\"realm\":\"example.com\",\"qop\":\"auth\",\"ha1\":\"ha1\"},\"aka\":{\"response\":\"response\"}}", 0, 30, 0L);
  ImpiStore::Impi* impi = impi_store->get_impi_with_nonce(IMPI, NONCE1, 0L);
  ASSERT_TRUE(impi != NULL);
  ASSERT_EQ(1, impi->auth_challenges.size());
  ASSERT_EQ(ImpiStore::AuthChallenge::Type::DIGEST, impi->auth_challenges[0]->type);
  delete impi;
}

TEST_F(ImpiStoreParsingTest, AVEmpty)
{
  local_store->set_data("av", IMPI + '\\' + NONCE1, "{}", 0, 30, 0L);
  ImpiStore::Impi* impi = impi_store->get_impi_with_nonce(IMPI, NONCE1, 0L);
  ASSERT_TRUE(impi != NULL);
  EXPECT_TRUE(impi->auth_challenges.empty());
  delete impi;
}

TEST_F(ImpiStoreParsingTest, AVDigestMissingRealm)
{
  local_store->set_data("av", IMPI + '\\' + NONCE1, "{\"digest\":{\"qop\":\"auth\",\"ha1\":\"ha1\"}}", 0, 30, 0L);
  ImpiStore::Impi* impi = impi_store->get_impi_with_nonce(IMPI, NONCE1, 0L);
  ASSERT_TRUE(impi != NULL);
  EXPECT_TRUE(impi->auth_challenges.empty());
  delete impi;
}

TEST_F(ImpiStoreParsingTest, AVDigestMissingQoP)
{
  local_store->set_data("av", IMPI + '\\' + NONCE1, "{\"digest\":{\"realm\":\"example.com\",\"ha1\":\"ha1\"}}", 0, 30, 0L);
  ImpiStore::Impi* impi = impi_store->get_impi_with_nonce(IMPI, NONCE1, 0L);
  ASSERT_TRUE(impi != NULL);
  EXPECT_TRUE(impi->auth_challenges.empty());
  delete impi;
}

TEST_F(ImpiStoreParsingTest, AVDigestMissingHA1)
{
  local_store->set_data("av", IMPI + '\\' + NONCE1, "{\"digest\":{\"realm\":\"example.com\",\"qop\":\"auth\"}}", 0, 30, 0L);
  ImpiStore::Impi* impi = impi_store->get_impi_with_nonce(IMPI, NONCE1, 0L);
  ASSERT_TRUE(impi != NULL);
  EXPECT_TRUE(impi->auth_challenges.empty());
  delete impi;
}

TEST_F(ImpiStoreParsingTest, AVDigestNotObject)
{
  local_store->set_data("av", IMPI + '\\' + NONCE1, "{\"digest\":\"not an objct\"}", 0, 30, 0L);
  ImpiStore::Impi* impi = impi_store->get_impi_with_nonce(IMPI, NONCE1, 0L);
  ASSERT_TRUE(impi != NULL);
  EXPECT_TRUE(impi->auth_challenges.empty());
  delete impi;
}

TEST_F(ImpiStoreParsingTest, AVDigestNCTombstone)
{
  local_store->set_data("av", IMPI + '\\' + NONCE1, "{\"digest\":{\"realm\":\"example.com\",\"qop\":\"auth\",\"ha1\":\"ha1\",\"nc\":5},\"tombstone\":true}", 0, 30, 0L);
  ImpiStore::Impi* impi = impi_store->get_impi_with_nonce(IMPI, NONCE1, 0L);
  ASSERT_TRUE(impi != NULL);
  ASSERT_EQ(1, impi->auth_challenges.size());
  ASSERT_EQ(6, impi->auth_challenges[0]->nonce_count);
  delete impi;
}

TEST_F(ImpiStoreParsingTest, AVDigestMissingNC1)
{
  local_store->set_data("av", IMPI + '\\' + NONCE1, "{\"digest\":{\"realm\":\"example.com\",\"qop\":\"auth\",\"ha1\":\"ha1\"}}", 0, 30, 0L);
  ImpiStore::Impi* impi = impi_store->get_impi_with_nonce(IMPI, NONCE1, 0L);
  ASSERT_TRUE(impi != NULL);
  ASSERT_EQ(1, impi->auth_challenges.size());
  ASSERT_EQ(1, impi->auth_challenges[0]->nonce_count);
  delete impi;
}

TEST_F(ImpiStoreParsingTest, AVDigestMissingNC2)
{
  local_store->set_data("av", IMPI + '\\' + NONCE1, "{\"digest\":{\"realm\":\"example.com\",\"qop\":\"auth\",\"ha1\":\"ha1\"},\"tombstone\":true}", 0, 30, 0L);
  ImpiStore::Impi* impi = impi_store->get_impi_with_nonce(IMPI, NONCE1, 0L);
  ASSERT_TRUE(impi != NULL);
  ASSERT_EQ(1, impi->auth_challenges.size());
  ASSERT_EQ(2, impi->auth_challenges[0]->nonce_count);
  delete impi;
}

TEST_F(ImpiStoreParsingTest, AVDigestExpiresInPast)
{
  local_store->set_data("av", IMPI + '\\' + NONCE1, "{\"digest\":{\"realm\":\"example.com\",\"qop\":\"auth\",\"ha1\":\"ha1\",\"expires\":1}}", 0, 30, 0L);
  ImpiStore::Impi* impi = impi_store->get_impi_with_nonce(IMPI, NONCE1, 0L);
  ASSERT_TRUE(impi != NULL);
  EXPECT_TRUE(impi->auth_challenges.empty());
  delete impi;
}

TEST_F(ImpiStoreParsingTest, AVDigestBranch)
{
  local_store->set_data("av", IMPI + '\\' + NONCE1, "{\"digest\":{\"realm\":\"example.com\",\"qop\":\"auth\",\"ha1\":\"ha1\"},\"branch\":\"correlator\"}", 0, 30, 0L);
  ImpiStore::Impi* impi = impi_store->get_impi_with_nonce(IMPI, NONCE1, 0L);
  ASSERT_TRUE(impi != NULL);
  ASSERT_EQ(1, impi->auth_challenges.size());
  ASSERT_EQ("correlator", impi->auth_challenges[0]->correlator);
  delete impi;
}

TEST_F(ImpiStoreParsingTest, AVAKAMissingResponse)
{
  local_store->set_data("av", IMPI + '\\' + NONCE1, "{\"aka\":{}}", 0, 30, 0L);
  ImpiStore::Impi* impi = impi_store->get_impi_with_nonce(IMPI, NONCE1, 0L);
  ASSERT_TRUE(impi != NULL);
  EXPECT_TRUE(impi->auth_challenges.empty());
  delete impi;
}

TEST_F(ImpiStoreParsingTest, AVAKANotObject)
{
  local_store->set_data("av", IMPI + '\\' + NONCE1, "{\"aka\":\"not an objct\"}", 0, 30, 0L);
  ImpiStore::Impi* impi = impi_store->get_impi_with_nonce(IMPI, NONCE1, 0L);
  ASSERT_TRUE(impi != NULL);
  EXPECT_TRUE(impi->auth_challenges.empty());
  delete impi;
}


/// Fixture for ImpiStoreSerializingTest.
///
/// These tests cover serialization of data to JSON.
class ImpiStoreSerializingTest : public ImpiStoreTest
{
public:
  ImpiStore* impi_store;
  ImpiStoreSerializingTest() :
    ImpiStoreTest(),
    impi_store(new ImpiStore(local_store, ImpiStore::Mode::READ_AV_IMPI_WRITE_AV_IMPI))
  {};
  virtual ~ImpiStoreSerializingTest()
  {
    delete impi_store;
  };
  rapidjson::Document* setAndGet(ImpiStore::Impi* impi)
  {
    Store::Status status = impi_store->set_impi(impi, 0L);
    EXPECT_EQ(Store::Status::OK, status);
    delete impi;

    std::string data;
    uint64_t cas;
    status = local_store->get_data("av", IMPI + '\\' + NONCE1, data, cas, 0L);
    EXPECT_EQ(Store::Status::OK, status);

    rapidjson::Document* json = new rapidjson::Document;
    json->Parse<0>(data.c_str());
    EXPECT_TRUE(!json->HasParseError());
    return json;
  };
};

TEST_F(ImpiStoreSerializingTest, Digest)
{
  ImpiStore::Impi* impi = example_impi_digest();
  rapidjson::Document* json = setAndGet(impi);
  ASSERT_TRUE((*json).IsObject());
  ASSERT_TRUE((*json).HasMember("digest"));
  ASSERT_TRUE((*json)["digest"].IsObject());
  delete json;
}

TEST_F(ImpiStoreSerializingTest, AKA)
{
  ImpiStore::Impi* impi = example_impi_aka();
  rapidjson::Document* json = setAndGet(impi);
  ASSERT_TRUE((*json).IsObject());
  ASSERT_TRUE((*json).HasMember("aka"));
  ASSERT_TRUE((*json)["aka"].IsObject());
  delete json;
}

TEST_F(ImpiStoreSerializingTest, DigestTombstone)
{
  ImpiStore::Impi* impi = example_impi_digest();
  impi->auth_challenges[0]->nonce_count++;
  uint32_t nonce_count = impi->auth_challenges[0]->nonce_count;
  rapidjson::Document* json = setAndGet(impi);
  ASSERT_TRUE((*json).IsObject());
  ASSERT_TRUE((*json).HasMember("digest"));
  ASSERT_TRUE((*json)["digest"].IsObject());
  ASSERT_TRUE((*json)["digest"].HasMember("nc"));
  ASSERT_TRUE((*json)["digest"]["nc"].IsUint());
  ASSERT_EQ(nonce_count - 1, (*json)["digest"]["nc"].GetUint());
  ASSERT_TRUE((*json).HasMember("tombstone"));
  ASSERT_TRUE((*json)["tombstone"].IsBool());
  ASSERT_TRUE((*json)["tombstone"].GetBool());
  delete json;
}

TEST_F(ImpiStoreSerializingTest, DigestExpired)
{
  ImpiStore::Impi* impi = example_impi_digest();
  impi->auth_challenges[0]->expires = 1;
  Store::Status status = impi_store->set_impi(impi, 0L);
  ASSERT_EQ(Store::Status::OK, status);
  delete impi;

  std::string data;
  uint64_t cas;
  status = local_store->get_data("av", IMPI + '\\' + NONCE1, data, cas, 0L);
  ASSERT_EQ(Store::Status::NOT_FOUND, status);
}

TEST_F(ImpiStoreSerializingTest, DigestCorrelator)
{
  ImpiStore::Impi* impi = example_impi_digest();
  rapidjson::Document* json = setAndGet(impi);
  ASSERT_TRUE((*json).IsObject());
  ASSERT_TRUE((*json).HasMember("branch"));
  ASSERT_TRUE((*json)["branch"].IsString());
  ASSERT_STREQ("correlator", (*json)["branch"].GetString());
  delete json;
}
