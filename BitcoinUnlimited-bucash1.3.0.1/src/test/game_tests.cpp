#include "data/script_tests.json.h"
#include "core_io.h"
#include "consensus/tx_verify.h"
#include "rpc/server.h"
#include "key.h"
#include "keystore.h"
#include "parallel.h"
#include "policy/policy.h"
#include "script/ismine.h"
#include "script/script_error.h"
#include "script/sign.h"
#if defined(HAVE_CONSENSUS_LIB)
#include "script/bitcoinconsensus.h"
#endif
#include "test/scriptflags.h"
#include "test/test_bitcoin.h"
#include <iostream>
#include <vector>

#include <boost/test/unit_test.hpp>
using namespace std;

static const unsigned int flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC | SCRIPT_ENABLE_SIGHASH_FORKID;

extern UniValue read_json(const std::string &jsondata);

struct ScriptErrorDesc
{
    ScriptError_t err;
    const char *name;
};

static ScriptErrorDesc script_errors[] = {
    {SCRIPT_ERR_OK, "OK"}, {SCRIPT_ERR_UNKNOWN_ERROR, "UNKNOWN_ERROR"}, {SCRIPT_ERR_EVAL_FALSE, "EVAL_FALSE"},
    {SCRIPT_ERR_OP_RETURN, "OP_RETURN"}, {SCRIPT_ERR_SCRIPT_SIZE, "SCRIPT_SIZE"}, {SCRIPT_ERR_PUSH_SIZE, "PUSH_SIZE"},
    {SCRIPT_ERR_OP_COUNT, "OP_COUNT"}, {SCRIPT_ERR_STACK_SIZE, "STACK_SIZE"}, {SCRIPT_ERR_SIG_COUNT, "SIG_COUNT"},
    {SCRIPT_ERR_PUBKEY_COUNT, "PUBKEY_COUNT"}, {SCRIPT_ERR_INVALID_OPERAND_SIZE, "OPERAND_SIZE"},
    {SCRIPT_ERR_INVALID_NUMBER_RANGE, "INVALID_NUMBER_RANGE"}, {SCRIPT_ERR_INVALID_SPLIT_RANGE, "SPLIT_RANGE"},
    {SCRIPT_ERR_VERIFY, "VERIFY"}, {SCRIPT_ERR_EQUALVERIFY, "EQUALVERIFY"},
    {SCRIPT_ERR_CHECKMULTISIGVERIFY, "CHECKMULTISIGVERIFY"}, {SCRIPT_ERR_CHECKSIGVERIFY, "CHECKSIGVERIFY"},
    {SCRIPT_ERR_NUMEQUALVERIFY, "NUMEQUALVERIFY"}, {SCRIPT_ERR_BAD_OPCODE, "BAD_OPCODE"},
    {SCRIPT_ERR_DISABLED_OPCODE, "DISABLED_OPCODE"}, {SCRIPT_ERR_INVALID_STACK_OPERATION, "INVALID_STACK_OPERATION"},
    {SCRIPT_ERR_INVALID_ALTSTACK_OPERATION, "INVALID_ALTSTACK_OPERATION"},
    {SCRIPT_ERR_UNBALANCED_CONDITIONAL, "UNBALANCED_CONDITIONAL"}, {SCRIPT_ERR_NEGATIVE_LOCKTIME, "NEGATIVE_LOCKTIME"},
    {SCRIPT_ERR_UNSATISFIED_LOCKTIME, "UNSATISFIED_LOCKTIME"}, {SCRIPT_ERR_SIG_HASHTYPE, "SIG_HASHTYPE"},
    {SCRIPT_ERR_SIG_DER, "SIG_DER"}, {SCRIPT_ERR_MINIMALDATA, "MINIMALDATA"}, {SCRIPT_ERR_SIG_PUSHONLY, "SIG_PUSHONLY"},
    {SCRIPT_ERR_SIG_HIGH_S, "SIG_HIGH_S"}, {SCRIPT_ERR_SIG_NULLDUMMY, "SIG_NULLDUMMY"},
    {SCRIPT_ERR_PUBKEYTYPE, "PUBKEYTYPE"}, {SCRIPT_ERR_CLEANSTACK, "CLEANSTACK"}, {SCRIPT_ERR_SIG_NULLFAIL, "NULLFAIL"},
    {SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS, "DISCOURAGE_UPGRADABLE_NOPS"}, {SCRIPT_ERR_DIV_BY_ZERO, "DIV_BY_ZERO"},
    {SCRIPT_ERR_MOD_BY_ZERO, "MOD_BY_ZERO"},
};

extern const char *FormatScriptError(ScriptError_t err);
//{
//    for (unsigned int i = 0; i < ARRAYLEN(script_errors); ++i)
//        if (script_errors[i].err == err)
//            return script_errors[i].name;
//    BOOST_ERROR("Unknown scripterror enumeration value, update script_errors in script_tests.cpp.");
//    return "";
//}

//ScriptError_t ParseScriptError(const std::string &name)
//{
//    for (unsigned int i = 0; i < ARRAYLEN(script_errors); ++i)
//        if (script_errors[i].name == name)
//            return script_errors[i].err;
//    BOOST_ERROR("Unknown scripterror \"" << name << "\" in test description");
//    return SCRIPT_ERR_UNKNOWN_ERROR;
//}

BOOST_FIXTURE_TEST_SUITE(game_tests, BasicTestingSetup)

CMutableTransaction BuildCreditingTransaction(const CScript &scriptPubKey, CAmount nValue)
{
    CMutableTransaction txCredit;
    txCredit.nVersion = 1;
    txCredit.nLockTime = 0;
    txCredit.vin.resize(1);
    txCredit.vout.resize(1);
    txCredit.vin[0].prevout.SetNull();
    txCredit.vin[0].scriptSig = CScript() << CScriptNum(0) << CScriptNum(0);
    txCredit.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    txCredit.vout[0].scriptPubKey = scriptPubKey;
    txCredit.vout[0].nValue = nValue;

    return txCredit;
}

CMutableTransaction BuildSpendingTransaction(const CScript &scriptSig, const CMutableTransaction &txCredit)
{
    CMutableTransaction txSpend;
    txSpend.nVersion = 1;
    txSpend.nLockTime = 0;
    txSpend.vin.resize(1);
    txSpend.vout.resize(1);
    txSpend.vin[0].prevout.hash = txCredit.GetHash();
    txSpend.vin[0].prevout.n = 0;
    txSpend.vin[0].scriptSig = scriptSig;
    txSpend.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    txSpend.vout[0].scriptPubKey = CScript();
    txSpend.vout[0].nValue = txCredit.vout[0].nValue;

    return txSpend;
}

void DoTest(const CScript &scriptPubKey,
    const CScript &scriptSig,
    int flags,
    const std::string &message,
    int scriptError,
    CAmount nValue)
{
    bool expect = (scriptError == SCRIPT_ERR_OK);
    ScriptError err;
    CMutableTransaction txCredit = BuildCreditingTransaction(scriptPubKey, nValue);
    CMutableTransaction tx = BuildSpendingTransaction(scriptSig, txCredit);
    CMutableTransaction tx2 = tx;
    bool result = VerifyScript(scriptSig, scriptPubKey, flags,
        MutableTransactionSignatureChecker(&tx, 0, txCredit.vout[0].nValue, flags), &err);
    BOOST_CHECK_MESSAGE(result == expect, message);
    BOOST_CHECK_MESSAGE(err == scriptError, std::string(FormatScriptError(err)) + " where " +
                                                std::string(FormatScriptError((ScriptError_t)scriptError)) +
                                                " expected: " + message);
#if defined(HAVE_CONSENSUS_LIB)
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << tx2;
    if (nValue == 0)
    {
        BOOST_CHECK_MESSAGE(bitcoinconsensus_verify_script(begin_ptr(scriptPubKey), scriptPubKey.size(),
                                (const unsigned char *)&stream[0], stream.size(), 0, flags, NULL) == expect,
            message);
    }
#endif
}

void static NegateSignatureS(std::vector<unsigned char> &vchSig)
{
    // Parse the signature.
    std::vector<unsigned char> r, s;
    r = std::vector<unsigned char>(vchSig.begin() + 4, vchSig.begin() + 4 + vchSig[3]);
    s = std::vector<unsigned char>(
        vchSig.begin() + 6 + vchSig[3], vchSig.begin() + 6 + vchSig[3] + vchSig[5 + vchSig[3]]);

    // Really ugly to implement mod-n negation here, but it would be feature creep to expose such functionality from
    // libsecp256k1.
    static const unsigned char order[33] = {0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0,
        0x36, 0x41, 0x41};
    while (s.size() < 33)
    {
        s.insert(s.begin(), 0x00);
    }
    int carry = 0;
    for (int p = 32; p >= 1; p--)
    {
        int n = (int)order[p] - s[p] - carry;
        s[p] = (n + 256) & 0xFF;
        carry = (n < 0);
    }
    assert(carry == 0);
    if (s.size() > 1 && s[0] == 0 && s[1] < 0x80)
    {
        s.erase(s.begin());
    }

    // Reconstruct the signature.
    vchSig.clear();
    vchSig.push_back(0x30);
    vchSig.push_back(4 + r.size() + s.size());
    vchSig.push_back(0x02);
    vchSig.push_back(r.size());
    vchSig.insert(vchSig.end(), r.begin(), r.end());
    vchSig.push_back(0x02);
    vchSig.push_back(s.size());
    vchSig.insert(vchSig.end(), s.begin(), s.end());
}

namespace
{
const unsigned char vchKey0[32] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
const unsigned char vchKey1[32] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0};
const unsigned char vchKey2[32] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0};

struct KeyData
{
    CKey key0, key0C, key1, key1C, key2, key2C;
    CPubKey pubkey0, pubkey0C, pubkey0H;
    CPubKey pubkey1, pubkey1C;
    CPubKey pubkey2, pubkey2C;

    KeyData()
    {
        key0.Set(vchKey0, vchKey0 + 32, false);
        key0C.Set(vchKey0, vchKey0 + 32, true);
        pubkey0 = key0.GetPubKey();
        pubkey0H = key0.GetPubKey();
        pubkey0C = key0C.GetPubKey();
        *const_cast<unsigned char *>(&pubkey0H[0]) = 0x06 | (pubkey0H[64] & 1);

        key1.Set(vchKey1, vchKey1 + 32, false);
        key1C.Set(vchKey1, vchKey1 + 32, true);
        pubkey1 = key1.GetPubKey();
        pubkey1C = key1C.GetPubKey();

        key2.Set(vchKey2, vchKey2 + 32, false);
        key2C.Set(vchKey2, vchKey2 + 32, true);
        pubkey2 = key2.GetPubKey();
        pubkey2C = key2C.GetPubKey();
    }
};


class TestBuilder
{
private:
    //! Actually executed script
    CScript script;
    //! The P2SH redeemscript
    CScript redeemscript;
    CTransactionRef creditTx;
    CMutableTransaction spendTx;
    bool havePush;
    std::vector<unsigned char> push;
    std::string comment;
    int flags;
    int scriptError;
    CAmount nValue;

    void DoPush()
    {
        if (havePush)
        {
            spendTx.vin[0].scriptSig << push;
            havePush = false;
        }
    }

    void DoPush(const std::vector<unsigned char> &data)
    {
        DoPush();
        push = data;
        havePush = true;
    }

public:
    TestBuilder(const CScript &script_, const std::string &comment_, int flags_, bool P2SH = false, CAmount nValue_ = 0)
        : script(script_), havePush(false), comment(comment_), flags(flags_), scriptError(SCRIPT_ERR_OK),
          nValue(nValue_)
    {
        CScript scriptPubKey = script;
        if (P2SH)
        {
            redeemscript = scriptPubKey;
            scriptPubKey = CScript() << OP_HASH160 << ToByteVector(CScriptID(redeemscript)) << OP_EQUAL;
        }
        creditTx = MakeTransactionRef(BuildCreditingTransaction(scriptPubKey, nValue));
        spendTx = BuildSpendingTransaction(CScript(), *creditTx);
    }

    TestBuilder &ScriptError(ScriptError_t err)
    {
        scriptError = err;
        return *this;
    }

    TestBuilder &Add(const CScript &script)
    {
        DoPush();
        spendTx.vin[0].scriptSig += script;
        return *this;
    }

    TestBuilder &Num(int num)
    {
        DoPush();
        spendTx.vin[0].scriptSig << num;
        return *this;
    }

    TestBuilder &Push(const std::string &hex)
    {
        DoPush(ParseHex(hex));
        return *this;
    }

    TestBuilder &PushSig(const CKey &key,
        int nHashType = SIGHASH_ALL,
        unsigned int lenR = 32,
        unsigned int lenS = 32,
        CAmount amount = 0)
    {
        uint256 hash = SignatureHash(script, spendTx, 0, nHashType, amount);
        std::vector<unsigned char> vchSig, r, s;
        uint32_t iter = 0;
        do
        {
            key.Sign(hash, vchSig, iter++);
            if ((lenS == 33) != (vchSig[5 + vchSig[3]] == 33))
            {
                NegateSignatureS(vchSig);
            }
            r = std::vector<unsigned char>(vchSig.begin() + 4, vchSig.begin() + 4 + vchSig[3]);
            s = std::vector<unsigned char>(
                vchSig.begin() + 6 + vchSig[3], vchSig.begin() + 6 + vchSig[3] + vchSig[5 + vchSig[3]]);
        } while (lenR != r.size() || lenS != s.size());
        vchSig.push_back(static_cast<unsigned char>(nHashType));
        DoPush(vchSig);
        return *this;
    }

    TestBuilder &Push(const CPubKey &pubkey)
    {
        DoPush(std::vector<unsigned char>(pubkey.begin(), pubkey.end()));
        return *this;
    }

    TestBuilder &PushRedeem()
    {
        DoPush(std::vector<unsigned char>(redeemscript.begin(), redeemscript.end()));
        return *this;
    }

    TestBuilder &EditPush(unsigned int pos, const std::string &hexin, const std::string &hexout)
    {
        assert(havePush);
        std::vector<unsigned char> datain = ParseHex(hexin);
        std::vector<unsigned char> dataout = ParseHex(hexout);
        assert(pos + datain.size() <= push.size());
        BOOST_CHECK_MESSAGE(
            std::vector<unsigned char>(push.begin() + pos, push.begin() + pos + datain.size()) == datain, comment);
        push.erase(push.begin() + pos, push.begin() + pos + datain.size());
        push.insert(push.begin() + pos, dataout.begin(), dataout.end());
        return *this;
    }

    TestBuilder &DamagePush(unsigned int pos)
    {
        assert(havePush);
        assert(pos < push.size());
        push[pos] ^= 1;
        return *this;
    }

    TestBuilder &Test()
    {
        TestBuilder copy = *this; // Make a copy so we can rollback the push.
        DoPush();
        DoTest(creditTx->vout[0].scriptPubKey, spendTx.vin[0].scriptSig, flags, comment, scriptError, nValue);
        *this = copy;
        return *this;
    }

    UniValue GetJSON()
    {
        DoPush();
        UniValue array(UniValue::VARR);
        if (nValue != 0)
        {
            UniValue amount(UniValue::VARR);
            amount.push_back(ValueFromAmount(nValue));
            array.push_back(amount);
        }
        array.push_back(FormatScript(spendTx.vin[0].scriptSig));
        array.push_back(FormatScript(creditTx->vout[0].scriptPubKey));
        array.push_back(FormatScriptFlags(flags));
        array.push_back(FormatScriptError((ScriptError_t)scriptError));
        array.push_back(comment);
        return array;
    }

    std::string GetComment() { return comment; }
    const CScript &GetScriptPubKey() { return creditTx->vout[0].scriptPubKey; }
};

std::string JSONPrettyPrint(const UniValue &univalue)
{
    std::string ret = univalue.write(4);
    // Workaround for libunivalue pretty printer, which puts a space between comma's and newlines
    size_t pos = 0;
    while ((pos = ret.find(" \n", pos)) != std::string::npos)
    {
        ret.replace(pos, 2, "\n");
        pos++;
    }
    return ret;
}
}


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


BOOST_AUTO_TEST_CASE(sign_game)
{

	cout << "sign_game begin ----------------------------------------" << endl;
	cout << endl;
	cout << endl;

	std::vector<unsigned char> dataA(1);
	dataA[0] = 3;
	QuickAddress addrA;
	std::vector<unsigned char> sigtypeA(66);
	sigtypeA = signmessage(dataA, addrA.secret);
	sigtypeA.push_back(DATASIG_COMPACT_ECDSA);

	std::vector<unsigned char> dataB(1);
	dataB[0] = 5;
	QuickAddress addrB;
	std::vector<unsigned char> sigtypeB(66);
	sigtypeB = signmessage(dataB, addrB.secret);
	sigtypeB.push_back(DATASIG_COMPACT_ECDSA);

	std::vector<unsigned char> dataMod(1);
	dataMod[0] = 2;

	CScript proveScript ;//= CScript() << dataA << sigtypeA << dataB << sigtypeB;
	CScript condScript; //= CScript() << ToByteVector(addrB.addr) << OP_DATASIGVERIFY << OP_ROT << OP_ROT << ToByteVector(addrA.addr) << OP_DATASIGVERIFY;
	//condScript << OP_ADD << data2 << OP_MOD;

	condScript << OP_DUP << dataA << OP_EQUALVERIFY << ToByteVector(addrA.addr) << OP_DATASIGVERIFY << OP_ROT << OP_ROT 
			  << OP_DUP << dataB << OP_EQUALVERIFY << ToByteVector(addrB.addr) << OP_DATASIGVERIFY << OP_ADD << dataMod 
			  << OP_IF  << OP_DUP << OP_HASH160 << ToByteVector(addrB.addr) << OP_EQUALVERIFY << OP_CHECKSIG << OP_ELSE 
			  << OP_DUP << OP_HASH160 << ToByteVector(addrA.addr) << OP_EQUALVERIFY << OP_CHECKSIG << OP_ENDIF;
	
	CScript p2shScript = GetScriptForDestination(CScriptID(condScript));
	std::cout  << "p2sh  address: " << FormatScript(p2shScript) << std::endl;
	std::vector<std::vector<unsigned char> > stack;
	ScriptError serror;
	BaseSignatureChecker sigChecker;
	enableDataSigVerify = true;

	std::cerr << "====================================================" << std::endl;
	std::cerr << "GetSigOpCount: " << condScript.GetSigOpCount(true) << std::endl;

	// check basic success case
	stack.clear() ; 
	
	BOOST_CHECK(EvalScript(stack, proveScript, 0, sigChecker, &serror, nullptr));

	std::cerr << "stack.size(): " << stack.size() << std::endl;
	for (size_t i = 0; i < stack.size(); i++) 
	{
		std::cerr << "stack[" << i << "]: " << std::endl;
		for (auto &tt: stack[i])
			printf("%x", tt);
		std::cerr << std::endl;
	}
	
	unsigned int flag  =  (1U << 18);
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

	

	cout  << endl;
	cout  << endl;
	cout << "game_sign --------------------------------------------------------" << endl;

}

CScript sign_multisig_game(const CScript &scriptPubKey, std::vector<CKey> keys, const CTransaction &transaction, CAmount amt)
{
	unsigned char sighashType = SIGHASH_ALL | SIGHASH_FORKID;

	uint256 hash = SignatureHash(scriptPubKey, transaction, 0, sighashType, amt, 0);

	CScript result;
	//
	// NOTE: CHECKMULTISIG has an unfortunate bug; it requires
	// one extra item on the stack, before the signatures.
	// Putting OP_0 on the stack is the workaround;
	// fixing the bug would mean splitting the block chain (old
	// clients would not accept new CHECKMULTISIG transactions,
	// and vice-versa)
	//
	result << OP_0;
	BOOST_FOREACH (const CKey &key, keys)
	{
		vector<unsigned char> vchSig;
		BOOST_CHECK(key.Sign(hash, vchSig));
		vchSig.push_back(sighashType);
		result << vchSig;
	}
	return result;
}

CScript sign_multisig_game(const CScript &scriptPubKey, const CKey &key, const CTransaction &transaction, CAmount amt)
{
	std::vector<CKey> keys;
	keys.push_back(key);
	return sign_multisig_game(scriptPubKey, keys, transaction, amt);
}


BOOST_AUTO_TEST_CASE(tx_game)
{
	//  OP_DUP 494d7a396474696f6555394f386d7845647531777343374d6c2b497078734c397a523658734c713255794563656c30453036343064767934324936503830675176464e676a4f305441705a647277366d616f6853434f413d OP_EQUALVERIFY 554065fae3af60b66269ef056c36c163b60365d7 OP_UNKNOWN OP_ROT OP_ROT OP_DUP 494d7a396474696f6555394f386d7845647531777343374d6c2b497078734c397a523658734c713255794563656c30453036343064767934324936503830675176464e676a4f305441705a647277366d616f6853434f413d OP_EQUALVERIFY 7ff50f205dd14626d41b667246165c5ef846248d OP_UNKNOWN OP_ADD 2 OP_MOD OP_IF OP_DUP OP_HASH160 7ff50f205dd14626d41b667246165c5ef846248d OP_EQUALVERIFY OP_CHECKSIG OP_ELSE OP_DUP OP_HASH160 554065fae3af60b66269ef056c36c163b60365d7 OP_EQUALVERIFY OP_CHECKSIG END_IF
//	ScriptError err;
//	CKey keyA, keyB;
//	keyA.MakeNewKey(true);
//	keyB.MakeNewKey(true);



//	CScript scriptPubKeyAB;
//	scriptPubKeyAB << OP_1 << ToByteVector(key1.GetPubKey()) << ToByteVector(key2.GetPubKey()) << OP_2
//		<< OP_CHECKMULTISIG;
//

	typedef vector<unsigned char> valtype;
	std::vector<unsigned char> dataA(1);
	dataA[0] = 6;
	QuickAddress addrA;
	std::vector<unsigned char> sigtypeA(66);
	sigtypeA = signmessage(dataA, addrA.secret);
	sigtypeA.push_back(DATASIG_COMPACT_ECDSA);

	std::vector<unsigned char> dataB(1);
	dataB[0] = 23;
	QuickAddress addrB;
	std::vector<unsigned char> sigtypeB(66);
	sigtypeB = signmessage(dataB, addrB.secret);
	sigtypeB.push_back(DATASIG_COMPACT_ECDSA);

	std::vector<unsigned char> dataMod(1);
	dataMod[0] = 2;

//	CScript proveScript = CScript() << dataA << sigtypeA << dataB << sigtypeB;
//	CScript condScript = CScript() << ToByteVector(addrB.addr) << OP_DATASIGVERIFY << OP_ROT << OP_ROT << ToByteVector(addrA.addr) << OP_DATASIGVERIFY;
//	condScript << OP_ADD << data2 << OP_MOD;
//	CScript p2shScript = GetScriptForDestination(CScriptID(condScript));
		
	CScript scriptABVin ;
	scriptABVin << OP_DUP << sigtypeA  << OP_EQUALVERIFY << ToByteVector(addrA.addr) << OP_DATASIGVERIFY << OP_ROT << OP_ROT 
				<< OP_DUP << sigtypeB  << OP_EQUALVERIFY << ToByteVector(addrB.addr) << OP_DATASIGVERIFY << OP_ADD << dataMod  
				<< OP_MOD << OP_IF  << OP_DUP << OP_HASH160 << ToByteVector(addrA.addr) << OP_EQUALVERIFY << OP_CHECKSIG << OP_ELSE 
				<< OP_DUP << OP_HASH160 << ToByteVector(addrB.addr) << OP_EQUALVERIFY << OP_CHECKSIG << OP_ENDIF;
	
	CScript p2shABVin = GetScriptForDestination(CScriptID(scriptABVin));

	CMutableTransaction txFromAB = BuildCreditingTransaction(scriptABVin, 1);
	CMutableTransaction txToAB = BuildSpendingTransaction(CScript(), txFromAB);

	unsigned int flag  =  (1U << 18);
	unsigned int game_flag = flag + flags;
	ScriptError err;
	CScript scriptPubA;
	scriptPubA << ToByteVector(addrA.pubkey) ;
	CScript goodsig1 = sign_multisig_game(scriptPubA, addrA.secret, CTransaction(txToAB), txFromAB.vout[0].nValue);
	CScript proveScript;
	proveScript  << valtype(goodsig1.begin(),goodsig1.end()) << dataB << sigtypeB  << dataA << sigtypeA; 
	BOOST_CHECK(VerifyScript(proveScript, scriptABVin, game_flag,
				MutableTransactionSignatureChecker(&txToAB, 0, txFromAB.vout[0].nValue), &err));
//	BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));
//	txTo12.vout[0].nValue = 2;
//	BOOST_CHECK(!VerifyScript(goodsig1, scriptPubKey12, flags,
//				MutableTransactionSignatureChecker(&txTo12, 0, txFrom12.vout[0].nValue), &err));
//	BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_EVAL_FALSE, ScriptErrorString(err));
//
//	CScript goodsig2 = sign_multisig(scriptPubKey12, key2, txTo12, txFrom12.vout[0].nValue);
//	BOOST_CHECK(VerifyScript(goodsig2, scriptPubKey12, flags,
//				MutableTransactionSignatureChecker(&txTo12, 0, txFrom12.vout[0].nValue), &err));
//	BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));
//
//	CScript badsig1 = sign_multisig(scriptPubKey12, key3, txTo12, txFrom12.vout[0].nValue);
//	BOOST_CHECK(!VerifyScript(
//				badsig1, scriptPubKey12, flags, MutableTransactionSignatureChecker(&txTo12, 0, txFrom12.vout[0].nValue), &err));
//	BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_EVAL_FALSE, ScriptErrorString(err));}
	
}

BOOST_AUTO_TEST_SUITE_END()
