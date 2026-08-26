// Copyright (c) 2022-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <wallet/test/util.h>
#include <wallet/wallet.h>
#include <test/util/common.h>
#include <test/util/logging.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

namespace wallet {

BOOST_AUTO_TEST_SUITE(walletload_tests)

class DummyDescriptor final : public Descriptor {
private:
    std::string desc;
public:
    explicit DummyDescriptor(const std::string& descriptor) : desc(descriptor) {};
    ~DummyDescriptor() = default;

    std::string ToString(bool compat_format) const override { return desc; }
    std::optional<OutputType> GetOutputType() const override { return OutputType::UNKNOWN; }

    bool IsRange() const override { return false; }
    bool IsSolvable() const override { return false; }
    bool IsSingleType() const override { return true; }
    bool HavePrivateKeys(const SigningProvider&) const override { return false; }
    bool ToPrivateString(const SigningProvider& provider, std::string& out) const override { return false; }
    bool ToNormalizedString(const SigningProvider& provider, std::string& out, const DescriptorCache* cache = nullptr) const override { return false; }
    bool Expand(int pos, const SigningProvider& provider, std::vector<CScript>& output_scripts, FlatSigningProvider& out, DescriptorCache* write_cache = nullptr) const override { return false; };
    bool ExpandFromCache(int pos, const DescriptorCache& read_cache, std::vector<CScript>& output_scripts, FlatSigningProvider& out) const override { return false; }
    void ExpandPrivate(int pos, const SigningProvider& provider, FlatSigningProvider& out) const override {}
    std::optional<int64_t> ScriptSize() const override { return {}; }
    std::optional<int64_t> MaxSatisfactionWeight(bool) const override { return {}; }
    std::optional<int64_t> MaxSatisfactionElems() const override { return {}; }
    void GetPubKeys(std::set<CPubKey>& pubkeys, std::set<CExtPubKey>& ext_pubs) const override {}
    bool HasScripts() const override { return true; }
    std::vector<std::string> Warnings() const override { return {}; }
    uint32_t GetMaxKeyExpr() const override { return 0; }
    size_t GetKeyCount() const override { return 0; }
    bool CanSelfExpand() const final { return false; }
};

BOOST_FIXTURE_TEST_CASE(wallet_load_descriptors, TestingSetup)
{
    bilingual_str _error;
    std::vector<bilingual_str> _warnings;
    std::unique_ptr<WalletDatabase> database = CreateMockableWalletDatabase();
    {
        // Write unknown active descriptor
        WalletBatch batch(*database);
        std::string unknown_desc = "trx(tpubD6NzVbkrYhZ4Y4S7m6Y5s9GD8FqEMBy56AGphZXuagajudVZEnYyBahZMgHNCTJc2at82YX6s8JiL1Lohu5A3v1Ur76qguNH4QVQ7qYrBQx/86'/1'/0'/0/*)#8pn8tzdt";
        WalletDescriptor wallet_descriptor(std::make_shared<DummyDescriptor>(unknown_desc), 0, 0, 0, 0);
        BOOST_CHECK(batch.WriteDescriptor(uint256(), wallet_descriptor));
        BOOST_CHECK(batch.WriteActiveScriptPubKeyMan(static_cast<uint8_t>(OutputType::UNKNOWN), uint256(), false));
    }

    {
        // Now try to load the wallet and verify the error.
        const std::shared_ptr<CWallet> wallet(new CWallet(m_node.chain.get(), "", std::move(database)));
        BOOST_CHECK_EQUAL(wallet->PopulateWalletFromDB(_error, _warnings), DBErrors::UNKNOWN_DESCRIPTOR);
    }

    // Test 2
    // Now write a valid descriptor with an invalid ID.
    // As the software produces another ID for the descriptor, the loading process must be aborted.
    database = CreateMockableWalletDatabase();

    // Verify the error
    bool found = false;
    DebugLogHelper logHelper("The descriptor ID calculated by the wallet differs from the one in DB", [&](const std::string* s) {
        found = true;
        return false;
    });

    {
        // Write valid descriptor with invalid ID
        WalletBatch batch(*database);
        std::string desc = "wpkh([d34db33f/84h/0h/0h]xpub6DJ2dNUysrn5Vt36jH2KLBT2i1auw1tTSSomg8PhqNiUtx8QX2SvC9nrHu81fT41fvDUnhMjEzQgXnQjKEu3oaqMSzhSrHMxyyoEAmUHQbY/0/*)#cjjspncu";
        WalletDescriptor wallet_descriptor(std::make_shared<DummyDescriptor>(desc), 0, 0, 0, 0);
        BOOST_CHECK(batch.WriteDescriptor(uint256::ONE, wallet_descriptor));
    }

    {
        // Now try to load the wallet and verify the error.
        const std::shared_ptr<CWallet> wallet(new CWallet(m_node.chain.get(), "", std::move(database)));
        BOOST_CHECK_EQUAL(wallet->PopulateWalletFromDB(_error, _warnings), DBErrors::CORRUPT);
        BOOST_CHECK(found); // The error must be logged
    }
}

BOOST_FIXTURE_TEST_CASE(wallet_load_unordered_reorders_position_index, TestingSetup)
{
    // Simulate a legacy wallet where one tx record was never assigned an
    // order position (nOrderPos == -1). Loading such a wallet triggers
    // CWallet::ReorderTransactions(), which assigns it a position consistent
    // with nTimeReceived. Verify that the fix is actually reflected when
    // transactions are iterated in position order, not just that the
    // nOrderPos field on the object itself ends up correct.
    auto database = CreateMockableWalletDatabase();

    auto make_wtx = [](CAmount vout_value, unsigned int time_received, int64_t order_pos) {
        CMutableTransaction mtx;
        mtx.vin.emplace_back();
        mtx.vout.emplace_back(vout_value, CScript() << OP_TRUE);
        CWalletTx wtx{MakeTransactionRef(std::move(mtx)), TxStateInactive{}};
        wtx.nTimeReceived = time_received;
        wtx.nOrderPos = order_pos;
        return wtx;
    };

    CWalletTx wtx_a{make_wtx(1 * COIN, 100, 0)};
    CWalletTx wtx_b{make_wtx(2 * COIN, 200, 1)};
    // wtx_c is the chronologically newest transaction, but simulates a
    // legacy record that never had an order position assigned.
    CWalletTx wtx_c{make_wtx(3 * COIN, 300, -1)};

    {
        auto batch = database->MakeBatch();
        BOOST_CHECK(batch->Write(std::make_pair(DBKeys::TX, wtx_a.GetHash()), wtx_a));
        BOOST_CHECK(batch->Write(std::make_pair(DBKeys::TX, wtx_b.GetHash()), wtx_b));
        BOOST_CHECK(batch->Write(std::make_pair(DBKeys::TX, wtx_c.GetHash()), wtx_c));
    }

    const std::shared_ptr<CWallet> wallet(new CWallet(m_node.chain.get(), "", std::move(database)));
    bilingual_str error;
    std::vector<bilingual_str> warnings;
    BOOST_CHECK_EQUAL(wallet->PopulateWalletFromDB(error, warnings), DBErrors::LOAD_OK);

    LOCK(wallet->cs_wallet);
    // wtx_c is the newest transaction by nTimeReceived, so after
    // ReorderTransactions() runs it must be the *last* entry when
    // transactions are iterated in position order.
    std::vector<Txid> order;
    for (const auto& wtx : wallet->m_txs_by_pos) {
        order.push_back(wtx.GetHash());
    }
    BOOST_REQUIRE_EQUAL(order.size(), 3);
    BOOST_CHECK_EQUAL(order.back(), wtx_c.GetHash());
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
