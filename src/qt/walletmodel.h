// Copyright (c) 2011-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_WALLETMODEL_H
#define BITCOIN_QT_WALLETMODEL_H

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <key.h>
#include <script/standard.h>

#include <qt/walletmodeltransaction.h>

#include <interfaces/wallet.h>
#include <support/allocators/secure.h>

#include <map>
#include <vector>
#include <atomic>

#include <QObject>
<<<<<<< HEAD
#include <QMessageBox>
=======
#include <QStringList>
#include <QThread>
>>>>>>> project-a/time/qtumcore0.21

enum class OutputType;

class AddressTableModel;
class ClientModel;
class OptionsModel;
class PlatformStyle;
class RecentRequestsTableModel;
class SendCoinsRecipient;
class TransactionTableModel;
class WalletModelTransaction;
class DelegationItemModel;
class TokenTransactionTableModel;
class ContractTableModel;
class WalletWorker;
class TokenItemModel;
class SuperStakerItemModel;
class DelegationStakerItemModel;

class CCoinControl;
class CKeyID;
class COutPoint;
class COutput;
class CCoinControlEntry;
class CPubKey;
class uint256;
class UniValue;

namespace interfaces {
class Node;
} // namespace interfaces

QT_BEGIN_NAMESPACE
class QTimer;
QT_END_NAMESPACE

/** Interface to Bitcoin wallet from Qt view code. */
class WalletModel : public QObject
{
    Q_OBJECT

public:
    explicit WalletModel(std::unique_ptr<interfaces::Wallet> wallet, ClientModel& client_model, const PlatformStyle *platformStyle, QObject *parent = nullptr);
    ~WalletModel();

    enum StatusCode // Returned by sendCoins
    {
        OK,
        InvalidAmount,
        InvalidAddress,
        AmountExceedsBalance,
        AmountWithFeeExceedsBalance,
        DuplicateAddress,
        TransactionCreationFailed, // Error returned when wallet is still locked
        AbsurdFee,
        PaymentRequestExpired
    };

    enum EncryptionStatus
    {
        Unencrypted,  // !wallet->IsCrypted()
        Locked,       // wallet->IsCrypted() && wallet->IsLocked()
        Unlocked,     // wallet->IsCrypted() && !wallet->IsLocked()
        UnlockedForStaking
    };

    OptionsModel *getOptionsModel();
    AddressTableModel *getAddressTableModel();
    ContractTableModel *getContractTableModel();
    TransactionTableModel *getTransactionTableModel();
    RecentRequestsTableModel *getRecentRequestsTableModel();
    TokenItemModel *getTokenItemModel();
    TokenTransactionTableModel *getTokenTransactionTableModel();
    DelegationItemModel *getDelegationItemModel();
    SuperStakerItemModel *getSuperStakerItemModel();
    DelegationStakerItemModel *getDelegationStakerItemModel();

    EncryptionStatus getEncryptionStatus() const;

    // Check address for validity
    bool validateAddress(const QString &address, bool allow_stakeonly=false);

    // Return status record for SendCoins, contains error id + information
    struct SendCoinsReturn
    {
        SendCoinsReturn(StatusCode _status = OK, QString _reasonCommitFailed = "")
            : status(_status),
              reasonCommitFailed(_reasonCommitFailed)
        {
        }
        StatusCode status;
        QString reasonCommitFailed;
    };

    // prepare transaction for getting txfee before sending coins
    SendCoinsReturn prepareTransaction(WalletModelTransaction &transaction, const CCoinControl& coinControl);

    // Send coins to a list of recipients
    SendCoinsReturn sendCoins(WalletModelTransaction &transaction);

    // Wallet encryption
    bool setWalletEncrypted(bool encrypted, const SecureString &passphrase);
    // Passphrase only needed when unlocking
    bool setWalletLocked(bool locked, const SecureString &passPhrase=SecureString(), bool stakingOnly=false);
    bool setUnlockedForStaking();
    bool changePassphrase(const SecureString &oldPass, const SecureString &newPass);
    bool restoreWallet(const QString &filename, const QString &param);
    bool getWalletUnlockStakingOnly();
    void setWalletUnlockStakingOnly(bool unlock);

    // RAI object for unlocking wallet, returned by requestUnlock()
    class UnlockContext
    {
    public:
        UnlockContext(WalletModel *wallet, bool valid, bool relock, bool was_unlocked_for_staking);
        ~UnlockContext();

        bool isValid() const { return valid; }

        // Copy constructor is disabled.
        UnlockContext(const UnlockContext&) = delete;
        // Move operator and constructor transfer the context
        UnlockContext(UnlockContext&& obj) { CopyFrom(std::move(obj)); }
        UnlockContext& operator=(UnlockContext&& rhs) { CopyFrom(std::move(rhs)); return *this; }
    private:
        WalletModel *wallet;
        bool valid;
        mutable bool relock; // mutable, as it can be set to false by copying
<<<<<<< HEAD
        bool was_unlocked_for_staking;
=======
        bool stakingOnly;
>>>>>>> project-a/time/qtumcore0.21

        UnlockContext& operator=(const UnlockContext&) = default;
        void CopyFrom(UnlockContext&& rhs);
    };

    UnlockContext requestUnlock();


    void loadReceiveRequests(std::vector<std::string>& vReceiveRequests);
    bool saveReceiveRequest(const std::string &sAddress, const int64_t nId, const std::string &sRequest);

    bool bumpFee(uint256 hash, uint256& new_hash);

    static bool isWalletEnabled();

    void lockWallet();
    interfaces::Node& node() const { return m_node; }
    interfaces::Wallet& wallet() const { return *m_wallet; }
    ClientModel& clientModel() const { return *m_client_model; }
    void setClientModel(ClientModel* client_model);

    QString getWalletName() const;
    QString getDisplayName() const;

    bool isMultiwallet();

    QString getRestorePath();
    QString getRestoreParam();
    bool restore();

    uint64_t getStakeWeight();

    AddressTableModel* getAddressTableModel() const { return addressTableModel; }

    bool isHardwareLinkedWallet() const;
    bool tryCallRpc(const QString &sCommand, UniValue &rv, bool returnError=false) const;
    void warningBox(QString heading, QString msg) const;

    void refresh(bool pk_hash_only = false);

    uint256 getLastBlockProcessed() const;

//private:
    std::unique_ptr<interfaces::Wallet> m_wallet;
    std::unique_ptr<interfaces::Handler> m_handler_unload;
    std::unique_ptr<interfaces::Handler> m_handler_status_changed;
    std::unique_ptr<interfaces::Handler> m_handler_address_book_changed;
    std::unique_ptr<interfaces::Handler> m_handler_transaction_changed;
    std::unique_ptr<interfaces::Handler> m_handler_token_changed;
    std::unique_ptr<interfaces::Handler> m_handler_show_progress;
    std::unique_ptr<interfaces::Handler> m_handler_watch_only_changed;
    std::unique_ptr<interfaces::Handler> m_handler_can_get_addrs_changed;
    std::unique_ptr<interfaces::Handler> m_handler_contract_book_changed;
    ClientModel* m_client_model;
    interfaces::Node& m_node;

    std::unique_ptr<interfaces::Handler> m_handler_reserved_balance_changed;

    bool fHaveWatchOnly;
    bool fForceCheckBalanceChanged{false};

    // Wallet has an options model for wallet-specific options
    // (transaction fee, for example)
    OptionsModel *optionsModel;

    AddressTableModel *addressTableModel;
    ContractTableModel *contractTableModel;
    TransactionTableModel *transactionTableModel;
    RecentRequestsTableModel *recentRequestsTableModel;
    TokenItemModel *tokenItemModel;
    TokenTransactionTableModel *tokenTransactionTableModel;
    DelegationItemModel *delegationItemModel;
    SuperStakerItemModel *superStakerItemModel;
    DelegationStakerItemModel *delegationStakerItemModel;

    // Cache some values to be able to detect changes
    interfaces::WalletBalances m_cached_balances;
    EncryptionStatus cachedEncryptionStatus;
    QTimer* timer;

    // Block hash denoting when the last balance update was done.
    uint256 m_cached_last_update_tip{};

    int pollNum = 0;

    QString restorePath;
    QString restoreParam;

    uint64_t nWeight;
    std::atomic<bool> updateStakeWeight;
    std::atomic<bool> updateCoinAddresses;

    QThread t;
    WalletWorker *worker;

    void subscribeToCoreSignals();
    void unsubscribeFromCoreSignals();
<<<<<<< HEAD

    void checkBalanceChanged(const interfaces::WalletBalances& new_balances);
=======
    bool checkBalanceChanged(const interfaces::WalletBalances& new_balances);
    void checkTokenBalanceChanged();
    void checkDelegationChanged();
    void checkSuperStakerChanged();
>>>>>>> project-a/time/qtumcore0.21

Q_SIGNALS:
    // Signal that balance in wallet changed
    void balanceChanged(const interfaces::WalletBalances& balances);

    // Encryption status of wallet changed
    void encryptionStatusChanged();

    // Signal emitted when wallet needs to be unlocked
    // It is valid behaviour for listeners to keep the wallet locked after this signal;
    // this means that the unlocking failed or was cancelled.
    void requireUnlock();

    // Fired when a message should be reported to the user
    void message(const QString &title, const QString &message, unsigned int style) const;

    // Coins sent: from wallet, to recipient, in (serialized) transaction:
    void coinsSent(WalletModel* wallet, SendCoinsRecipient recipient, QByteArray transaction);

    // Show progress dialog e.g. for rescan
    void showProgress(const QString &title, int nProgress);

    // Watch-only address added
    void notifyWatchonlyChanged(bool fHaveWatchonly);

    // Signal that wallet is about to be removed
    void unload();

    // Notify that there are now keys in the keypool
    void canGetAddressesChanged();

<<<<<<< HEAD
    // Signal that reserved balance in wallet changed
    void notifyReservedBalanceChanged(CAmount nValue);
=======
    // Signal that available coin addresses are changed
    void availableAddressesChanged(QStringList spendableAddresses, QStringList allAddresses, bool includeZeroValue);
>>>>>>> project-a/time/qtumcore0.21

public Q_SLOTS:
    /* Starts a timer to periodically update the balance */
    void startPollBalance();

    /* Wallet status might have changed */
    void updateStatus();
    /* New transaction, or transaction changed status */
    void updateTransaction();
    /* New, updated or removed address book entry */
    void updateAddressBook(const QString &address, const QString &label, bool isMine, const QString &purpose, const QString &path, int status);
    /* Watch-only added */
    void updateWatchOnlyFlag(bool fHaveWatchonly);
    /* Current, immature or unconfirmed balance might have changed - emit 'balanceChanged' if so */
    void pollBalanceChanged();
<<<<<<< HEAD

    // Reserved balance changed
    void setReserveBalance(CAmount nReserveBalanceNew);

    // Reserved balance in wallet changed
    void updateReservedBalanceChanged(CAmount nValue);

    // Rescan blockchain for transactions
    void startRescan();
=======
    /* New, updated or removed contract book entry */
    void updateContractBook(const QString &address, const QString &label, const QString &abi, int status);
    /* Set that update for coin address is needed */
    void checkCoinAddresses();
    /* Update coin addresses when changed*/
    void checkCoinAddressesChanged();
    /* Update stake weight when changed*/
    void checkStakeWeightChanged();
>>>>>>> project-a/time/qtumcore0.21
};

#endif // BITCOIN_QT_WALLETMODEL_H
