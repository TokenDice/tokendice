// Copyright (c) 2012-2015 The Bitcoin Core developers
// Copyright (c) 2015-2017 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "test/test_bitcoin.h"
#include "util.h"

#include <string>
#include <vector>

#include <boost/algorithm/string.hpp>
#include <boost/foreach.hpp>
#include <boost/test/unit_test.hpp>

#include "data/script_tests.json.h"

#include "core_io.h"
#include "key.h"
#include "keystore.h"
#include "rpc/server.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/sign.h"
#include "test/scriptflags.h"
#include "utilstrencodings.h"

#if defined(HAVE_CONSENSUS_LIB)
#include "script/bitcoinconsensus.h"
#endif

#include <fstream>
#include <stdint.h>

#include <univalue.h>

BOOST_FIXTURE_TEST_SUITE(getarg_tests, BasicTestingSetup)

/*
enum Kind
{
    BITCOIND = 0,
    CONFIGFILE = 1,
    BITCOIN_CLI = 2
};

static void ResetArgs(const std::string &strArg, Kind kind = BITCOIND)
{
    std::vector<std::string> vecArg;
    if (strArg.size())
        boost::split(vecArg, strArg, boost::is_space(), boost::token_compress_on);

    // Insert dummy executable name:
    vecArg.insert(vecArg.begin(), "testbitcoin");

    // Convert to char*:
    std::vector<const char *> vecChar;
    BOOST_FOREACH (std::string &s, vecArg)
        vecChar.push_back(s.c_str());

    if (kind == CONFIGFILE)
        ParseParameters(vecChar.size(), &vecChar[0], AllowedArgs::ConfigFile(&tweaks));
    else if (kind == BITCOIND)
        ParseParameters(vecChar.size(), &vecChar[0], AllowedArgs::Bitcoind(&tweaks));
    else
        ParseParameters(vecChar.size(), &vecChar[0], AllowedArgs::BitcoinCli());
}

BOOST_AUTO_TEST_CASE(boolarg)
{
    ResetArgs("-listen");
    BOOST_CHECK(GetBoolArg("-listen", false));
    BOOST_CHECK(GetBoolArg("-listen", true));

    BOOST_CHECK(!GetBoolArg("-fo", false));
    BOOST_CHECK(GetBoolArg("-fo", true));

    BOOST_CHECK(!GetBoolArg("-fooo", false));
    BOOST_CHECK(GetBoolArg("-fooo", true));

    for (auto strValue : std::list<std::string>{"0", "f", "n", "false", "no"})
    {
        ResetArgs("-listen=" + strValue);
        BOOST_CHECK(!GetBoolArg("-listen", false));
        BOOST_CHECK(!GetBoolArg("-listen", true));
    }

    for (auto strValue : std::list<std::string>{"", "1", "t", "y", "true", "yes"})
    {
        ResetArgs("-listen=" + strValue);
        BOOST_CHECK(GetBoolArg("-listen", false));
        BOOST_CHECK(GetBoolArg("-listen", true));
    }

    // New 0.6 feature: auto-map -nosomething to !-something:
    ResetArgs("-nolisten");
    BOOST_CHECK(!GetBoolArg("-listen", false));
    BOOST_CHECK(!GetBoolArg("-listen", true));

    ResetArgs("-nolisten=1");
    BOOST_CHECK(!GetBoolArg("-listen", false));
    BOOST_CHECK(!GetBoolArg("-listen", true));

    ResetArgs("-listen -nolisten"); // -nolisten should win
    BOOST_CHECK(!GetBoolArg("-listen", false));
    BOOST_CHECK(!GetBoolArg("-listen", true));

    ResetArgs("-listen=1 -nolisten=1"); // -nolisten should win
    BOOST_CHECK(!GetBoolArg("-listen", false));
    BOOST_CHECK(!GetBoolArg("-listen", true));

    ResetArgs("-listen=0 -nolisten=0"); // -nolisten=0 should win
    BOOST_CHECK(GetBoolArg("-listen", false));
    BOOST_CHECK(GetBoolArg("-listen", true));

    // New 0.6 feature: treat -- same as -:
    ResetArgs("--listen=1");
    BOOST_CHECK(GetBoolArg("-listen", false));
    BOOST_CHECK(GetBoolArg("-listen", true));

    ResetArgs("--nolisten=1");
    BOOST_CHECK(!GetBoolArg("-listen", false));
    BOOST_CHECK(!GetBoolArg("-listen", true));

    BOOST_CHECK_THROW(ResetArgs("-listen=text"), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(stringarg)
{
    ResetArgs("");
    BOOST_CHECK_EQUAL(GetArg("-uacomment", ""), "");
    BOOST_CHECK_EQUAL(GetArg("-uacomment", "eleven"), "eleven");

    ResetArgs("-connect -listen"); // -connect is an optional string argument
    BOOST_CHECK_EQUAL(GetArg("-connect", ""), "");
    BOOST_CHECK_EQUAL(GetArg("-connect", "eleven"), "");

    ResetArgs("-connect=");
    BOOST_CHECK_EQUAL(GetArg("-connect", ""), "");
    BOOST_CHECK_EQUAL(GetArg("-connect", "eleven"), "");

    ResetArgs("-uacomment=11");
    BOOST_CHECK_EQUAL(GetArg("-uacomment", ""), "11");
    BOOST_CHECK_EQUAL(GetArg("-uacomment", "eleven"), "11");

    ResetArgs("-uacomment=eleven");
    BOOST_CHECK_EQUAL(GetArg("-uacomment", ""), "eleven");
    BOOST_CHECK_EQUAL(GetArg("-uacomment", "eleven"), "eleven");

    BOOST_CHECK_THROW(ResetArgs("-uacomment"), std::runtime_error);
    BOOST_CHECK_THROW(ResetArgs("-uacomment="), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(intarg)
{
    ResetArgs("");
    BOOST_CHECK_EQUAL(GetArg("-maxconnections", 11), 11);
    BOOST_CHECK_EQUAL(GetArg("-maxconnections", 0), 0);

    ResetArgs("-maxconnections"); // -maxconnections is an optional int argument
    BOOST_CHECK_EQUAL(GetArg("-maxconnections", 11), 0);

    ResetArgs("-maxconnections=11 -maxreceivebuffer=12");
    BOOST_CHECK_EQUAL(GetArg("-maxconnections", 0), 11);
    BOOST_CHECK_EQUAL(GetArg("-maxreceivebuffer", 11), 12);

    ResetArgs("-par=-1");
    BOOST_CHECK_EQUAL(GetArg("-par", 0), -1);

    BOOST_CHECK_THROW(ResetArgs("-maxreceivebuffer"), std::runtime_error);
    BOOST_CHECK_THROW(ResetArgs("-maxreceivebuffer="), std::runtime_error);
    BOOST_CHECK_THROW(ResetArgs("-maxreceivebuffer=NaN"), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(doubledash)
{
    ResetArgs("--listen");
    BOOST_CHECK_EQUAL(GetBoolArg("-listen", false), true);

    ResetArgs("--uacomment=verbose --maxconnections=1");
    BOOST_CHECK_EQUAL(GetArg("-uacomment", ""), "verbose");
    BOOST_CHECK_EQUAL(GetArg("-maxconnections", 0), 1);
}

BOOST_AUTO_TEST_CASE(boolargno)
{
    ResetArgs("-nolisten");
    BOOST_CHECK(!GetBoolArg("-listen", true));
    BOOST_CHECK(!GetBoolArg("-listen", false));

    ResetArgs("-nolisten=1");
    BOOST_CHECK(!GetBoolArg("-listen", true));
    BOOST_CHECK(!GetBoolArg("-listen", false));

    ResetArgs("-nolisten=0");
    BOOST_CHECK(GetBoolArg("-listen", true));
    BOOST_CHECK(GetBoolArg("-listen", false));

    ResetArgs("-listen --nolisten"); // --nolisten should win
    BOOST_CHECK(!GetBoolArg("-listen", true));
    BOOST_CHECK(!GetBoolArg("-listen", false));

    ResetArgs("-nolisten -listen"); // -listen always wins:
    BOOST_CHECK(GetBoolArg("-listen", true));
    BOOST_CHECK(GetBoolArg("-listen", false));
}

BOOST_AUTO_TEST_CASE(tweakArgs)
{
    ResetArgs("-mining.comment=I_Am_A_Meat_Popsicle -mining.coinbaseReserve=250 -wallet.maxTxFee=0.001");
    BOOST_CHECK_EQUAL(GetArg("-mining.comment", "foo"), "I_Am_A_Meat_Popsicle");
    BOOST_CHECK_EQUAL(GetArg("-mining.coinbaseReserve", 100), 250);
    BOOST_CHECK_EQUAL(GetArg("-wallet.maxTxFee", ""), "0.001");

    // Test ConfigFile accepts tweaks
    ResetArgs("-mining.comment=I_Am_A_Meat_Popsicle -mining.coinbaseReserve=250 -wallet.maxTxFee=0.001", CONFIGFILE);
    BOOST_CHECK_EQUAL(GetArg("-mining.comment", "foo"), "I_Am_A_Meat_Popsicle");
    BOOST_CHECK_EQUAL(GetArg("-mining.coinbaseReserve", 100), 250);
    BOOST_CHECK_EQUAL(GetArg("-wallet.maxTxFee", ""), "0.001");

    // Test ConfigFile rejects unknown tweaks
    BOOST_CHECK_THROW(ResetArgs("-some.tweak=something", CONFIGFILE), std::runtime_error);

    // Test bitcoin-cli accepts unknown tweaks
    ResetArgs("-some.tweak=something", BITCOIN_CLI);
    BOOST_CHECK_EQUAL(GetArg("-some.tweak", "default"), "something");
}

BOOST_AUTO_TEST_CASE(unrecognizedArgs)
{
    BOOST_CHECK_THROW(ResetArgs("-unrecognized_arg"), std::runtime_error);
    BOOST_CHECK_THROW(ResetArgs("-listen -unrecognized_arg"), std::runtime_error);
}
*/

/////////////////////////////////////////////////////

class QuickAddress
{
public:
    QuickAddress()
    {
        secret.MakeNewKey(true);
        pubkey = secret.GetPubKey();
        addr = pubkey.GetID();
    }
    QuickAddress(const CKey &k)
    {
        secret = k;
        pubkey = secret.GetPubKey();
        addr = pubkey.GetID();
    }
    QuickAddress(unsigned char key) // make a very simple key for testing only
    {
        secret.MakeNewKey(true);
        unsigned char *c = (unsigned char *)secret.begin();
        *c = key;
        c++;
        for (int i = 1; i < 32; i++, c++)
        {
            *c = 0;
        }
        pubkey = secret.GetPubKey();
        addr = pubkey.GetID();
    }

    CKey secret;
    CPubKey pubkey;
    CKeyID addr; // 160 bit normal address
};


BOOST_AUTO_TEST_CASE(verifymessage)
{
    std::vector<unsigned char> dataA(1);
    dataA[0] = 3;
    QuickAddress addrA;
    std::vector<unsigned char> sigtypeA(66);
    sigtypeA = signmessage(dataA, addrA.secret);
    sigtypeA.push_back(DATASIG_COMPACT_ECDSA);
	
	std::vector<unsigned char> dataB(1);
    dataB[0] = 4;
    QuickAddress addrB;
    std::vector<unsigned char> sigtypeB(66);
    sigtypeB = signmessage(dataB, addrB.secret);
    sigtypeB.push_back(DATASIG_COMPACT_ECDSA);
	
	CScript proveScript = CScript() << dataA << sigtypeA << dataB << sigtypeB;
    
	CScript condScript = CScript() << ToByteVector(addrB.addr) << OP_DATASIGVERIFY << OP_ROT << OP_ROT << ToByteVector(addrA.addr) << OP_DATASIGVERIFY;
	condScript << OP_ADD << 0x02 << OP_MOD;
	// condScript << OP_IF << OP_DUP << OP_HASH160 << ToByteVector(addrA.addr) << OP_EQUALVERIFY << OP_CHECKSIG;
	// condScript << OP_ELSE << OP_DUP << OP_HASH160 << ToByteVector(addrB.addr) << OP_EQUALVERIFY << OP_CHECKSIG << OP_ENDIF;
	
    std::vector<std::vector<unsigned char> > stack;
    ScriptError serror;
    BaseSignatureChecker sigChecker;
    enableDataSigVerify = true;
	
	std::cerr << "addrB.addr: " << addrB.addr.ToString() << std::endl;
	std::cerr << "====================================================" << std::endl;
	std::cerr << "GetSigOpCount: " << condScript.GetSigOpCount(true) << std::endl;

    // check basic success case
    stack.clear();
    BOOST_CHECK(EvalScript(stack, proveScript, 0, sigChecker, &serror, nullptr));
	
	std::cerr << "stack.size(): " << stack.size() << std::endl;
	for (size_t i = 0; i < stack.size(); i++) 
	{
		std::cerr << "stack[" << i << "]: " << std::endl;
		for (auto &tt: stack[i])
		    printf("%x", tt);
		std::cerr << std::endl;
	}
	
	unsigned int flag = (1U << 18);
    BOOST_CHECK(EvalScript(stack, condScript, flag, sigChecker, &serror, nullptr));
	
	std::cerr << "stack.size(): " << stack.size() << std::endl;
	for (size_t i = 0; i < stack.size(); i++) 
	{
		std::cerr << "stack[" << i << "]: " << std::endl;
		for (auto &tt: stack[i]) 
		    printf("%x", tt);
		std::cerr << std::endl;
	}
	std::cerr << "====================================================" << std::endl;
}


BOOST_AUTO_TEST_SUITE_END()
