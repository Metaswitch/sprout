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

/*
TODO: Remove?
class BacklevelImpiStoreImpl : public ImpiStoreImpl {
public:
  BacklevelImpiStoreImpl(Store* store) : _store(store) {};
  virtual Store::Status set_impi(ImpiStore::Impi* impi)
  {
    return _store->set_impi(impi);
  };
  virtual ImpiStore::Impi* get_impi(const std::string& impi)
  {
    return _store->get_impi(impi);
  };
  virtual ImpiStore::Impi* get_impi_with_nonce(const std::string& impi, const std::string& nonce)
  {
    return _store->get_impi_with_nonce(impi, nonce);
  };
  virtual Store::Status delete_impi(ImpiStore::Impi* impi)
  {
    return _store->delete_impi(impi);
  };
private:
  Store* store;
}
*/

class TwoStoreScenario
{
public:
  TwoStoreScenario(ImpiStoreImpl* _store1, ImpiStoreImpl* _store2) : store1(_store1), store2(_store2) {};
  ~TwoStoreScenario() {delete store1; delete store2;};
  ImpiStoreImpl* store1;
  ImpiStoreImpl* store2;
};

template<class T1, class T2>
class TwoStoreScenarioTemplate : public TwoStoreScenario
{
public:
  TwoStoreScenarioTemplate(Store* store) : TwoStoreScenario(new T1(store), new T2(store)) {};
};

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

const std::string IMPI = "private@example.com";
const std::string NONCE = "nonce";

ImpiStore::Impi* example_impi1()
{
  ImpiStore::Impi* impi = new ImpiStore::Impi(IMPI);
  ImpiStore::AuthChallenge* auth_challenge = new ImpiStore::DigestAuthChallenge(NONCE, "example.com", "auth", "ha1", 30000);
  auth_challenge->correlator = "correlator";
  impi->auth_challenges.push_back(auth_challenge);
  return impi;
};

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
  ImpiStore::Impi* impi1 = example_impi1();
  Store::Status status = this->impi_store->set_impi(impi1);
  ASSERT_EQ(Store::Status::OK, status);
  ImpiStore::Impi* impi2 = this->impi_store->get_impi(IMPI);
  expect_impis_equal(impi1, impi2);
  delete impi2;
  delete impi1;
}

TYPED_TEST(ImpiOneStoreTest, SetGetWithNonce)
{
  ImpiStore::Impi* impi1 = example_impi1();
  Store::Status status = this->impi_store->set_impi(impi1);
  ASSERT_EQ(Store::Status::OK, status);
  ImpiStore::Impi* impi2 = this->impi_store->get_impi_with_nonce(IMPI, NONCE);
  expect_impis_equal(impi1, impi2);
  delete impi2;
  delete impi1;
}

/// Fixture for ImpiTwoStoreTest.
///
/// The fixture is a template, parameterized over the different IMPI store
/// implementations.
template<class T> class ImpiTwoStoreTest : public ImpiStoreTest
{
public:
  TwoStoreScenario* scenario;
  ImpiTwoStoreTest() :
    ImpiStoreTest(),
    scenario(new T(local_store))
     {};
  virtual ~ImpiTwoStoreTest()
  {
    delete scenario;
  };
};

typedef ::testing::Types<
  TwoStoreScenarioTemplate<LiveImpiStoreImplAvImpi, LiveImpiStoreImplAvImpi>,
  TwoStoreScenarioTemplate<LiveImpiStoreImplAvImpi, LiveImpiStoreImplImpi>,
  TwoStoreScenarioTemplate<LiveImpiStoreImplImpi, LiveImpiStoreImplAvImpi>,
  TwoStoreScenarioTemplate<LiveImpiStoreImplImpi, LiveImpiStoreImplImpi>
> TwoStoreScenarios;

TYPED_TEST_CASE(ImpiTwoStoreTest, TwoStoreScenarios);

TYPED_TEST(ImpiTwoStoreTest, Set1Get2)
{
  ImpiStore::Impi* impi1 = example_impi1();
  Store::Status status = this->scenario->store1->set_impi(impi1);
  ASSERT_EQ(Store::Status::OK, status);
  ImpiStore::Impi* impi2 = this->scenario->store2->get_impi(IMPI);
  expect_impis_equal(impi1, impi2);
  delete impi2;
  delete impi1;
}

TYPED_TEST(ImpiTwoStoreTest, Set1GetNonce2)
{
  ImpiStore::Impi* impi1 = example_impi1();
  Store::Status status = this->scenario->store1->set_impi(impi1);
  ASSERT_EQ(Store::Status::OK, status);
  ImpiStore::Impi* impi2 = this->scenario->store2->get_impi_with_nonce(IMPI, NONCE);
  expect_impis_equal(impi1, impi2);
  delete impi2;
  delete impi1;
}

TYPED_TEST(ImpiTwoStoreTest, Write1Delete1Read2)
{
  ImpiStore::Impi* impi1 = example_impi1();
  Store::Status status = this->scenario->store1->set_impi(impi1);
  ASSERT_EQ(Store::Status::OK, status);
  status = this->scenario->store1->delete_impi(impi1);
  ASSERT_EQ(Store::Status::OK, status);
  ImpiStore::Impi* impi2 = this->scenario->store2->get_impi(IMPI);
  ASSERT_EQ(NULL, impi2);
  delete impi1;
}

/*
TYPED_TEST(ImpiTwoStoreTest, Write1Read2Write2Read1)
{
  ImpiStore::Impi* impi1 = example_impi1();
  Store::Status status = this->scenario->store1->set_impi(impi1);
  ASSERT_EQ(Store::Status::OK, status);
  ImpiStore::Impi* impi2 = this->scenario->store2->get_impi(IMPI);
  expect_impis_equal(impi1, impi2);
  ASSERT_TRUE(impi2 != NULL);
  status = this->scenario->store2->set_impi(impi2);
  ASSERT_EQ(Store::Status::OK, status);
  ImpiStore::Impi* impi3 = this->scenario->store1->get_impi(IMPI);
  expect_impis_equal(impi1, impi3);
  delete impi3;
  delete impi2;
  delete impi1;
}
*/

TYPED_TEST(ImpiTwoStoreTest, Write1ReadNonce2Write2ReadNonce1)
{
  ImpiStore::Impi* impi1 = example_impi1();
  Store::Status status = this->scenario->store1->set_impi(impi1);
  ASSERT_EQ(Store::Status::OK, status);
  ImpiStore::Impi* impi2 = this->scenario->store2->get_impi_with_nonce(IMPI, NONCE);
  expect_impis_equal(impi1, impi2);
  ASSERT_TRUE(impi2 != NULL);
  status = this->scenario->store2->set_impi(impi2);
  ASSERT_EQ(Store::Status::OK, status);
  ImpiStore::Impi* impi3 = this->scenario->store1->get_impi_with_nonce(IMPI, NONCE);
  expect_impis_equal(impi1, impi3);
  delete impi3;
  delete impi2;
  delete impi1;
}

/*
typedef ::testing::Types<
  TwoStoreScenarioTemplate<LiveImpiStoreImplAvImpi, LiveImpiStoreImplAvLostImpi>,
  TwoStoreScenarioTemplate<LiveImpiStoreImplImpi, LiveImpiStoreImplAvLostImpi>,
  TwoStoreScenarioTemplate<LiveImpiStoreImplAvLostImpi, LiveImpiStoreImplAvLostImpi>
> TwoStoreScenarios;
*/
