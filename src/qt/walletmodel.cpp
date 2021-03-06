// Copyright (c) 2011-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <qt/walletmodel.h>

#include <qt/addresstablemodel.h>
#include <qt/clientmodel.h>
#include <qt/guiconstants.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>
#include <qt/paymentserver.h>
#include <qt/recentrequeststablemodel.h>
#include <qt/sendcoinsdialog.h>
#include <qt/transactiontablemodel.h>
#include <qt/tokenitemmodel.h>
#include <qt/tokentransactiontablemodel.h>
#include <qt/contracttablemodel.h>
#include <qt/delegationitemmodel.h>
#include <qt/superstakeritemmodel.h>
#include <qt/delegationstakeritemmodel.h>

#include <interfaces/handler.h>
#include <interfaces/node.h>
#include <key_io.h>
#include <node/ui_interface.h>
#include <psbt.h>
#include <util/system.h> // for GetBoolArg
#include <util/translation.h>
#include <wallet/coincontrol.h>
#include <wallet/wallet.h> // for CRecipient

#include <wallet/hdwallet.h>
#include <rpc/rpcutil.h>
#include <util/system.h>
#include <univalue.h>
#include <util/ref.h>

#include <stdint.h>

#include <QDebug>
#include <QSet>
#include <QTimer>
<<<<<<< HEAD
#include <QApplication>
=======
#include <QFile>

static int pollSyncSkip = 30;

class WalletWorker : public QObject
{
    Q_OBJECT
public:
    WalletModel *walletModel;
    WalletWorker(WalletModel *_walletModel):
        walletModel(_walletModel){}

private Q_SLOTS:
    void updateModel()
    {
        if(walletModel && walletModel->node().shutdownRequested())
            return;

        // Update the model with results of task that take more time to be completed
        walletModel->checkCoinAddressesChanged();
        walletModel->checkStakeWeightChanged();
    }
};

#include <qt/walletmodel.moc>
>>>>>>> project-a/time/qtumcore0.21

WalletModel::WalletModel(std::unique_ptr<interfaces::Wallet> wallet, ClientModel& client_model, const PlatformStyle *platformStyle, QObject *parent) :
    QObject(parent),
    m_wallet(std::move(wallet)),
    m_client_model(&client_model),
    m_node(client_model.node()),
    optionsModel(client_model.getOptionsModel()),
    addressTableModel(nullptr),
    contractTableModel(nullptr),
    transactionTableModel(nullptr),
    recentRequestsTableModel(nullptr),
    tokenItemModel(nullptr),
    tokenTransactionTableModel(nullptr),
    delegationItemModel(nullptr),
    superStakerItemModel(nullptr),
    delegationStakerItemModel(nullptr),
    cachedEncryptionStatus(Unencrypted),
    timer(new QTimer(this)),
    nWeight(0),
    updateStakeWeight(true),
    updateCoinAddresses(true),
    worker(0)
{
    fHaveWatchOnly = m_wallet->haveWatchOnly();
    addressTableModel = new AddressTableModel(this);
    contractTableModel = new ContractTableModel(this);
    transactionTableModel = new TransactionTableModel(platformStyle, this);
    recentRequestsTableModel = new RecentRequestsTableModel(this);
    tokenItemModel = new TokenItemModel(this);
    tokenTransactionTableModel = new TokenTransactionTableModel(platformStyle, this);
    delegationItemModel = new DelegationItemModel(this);
    superStakerItemModel = new SuperStakerItemModel(this);
    delegationStakerItemModel = new DelegationStakerItemModel(this);

    worker = new WalletWorker(this);
    worker->moveToThread(&(t));
    t.start();

    connect(addressTableModel, SIGNAL(rowsInserted(QModelIndex,int,int)), this, SLOT(checkCoinAddresses()));
    connect(addressTableModel, SIGNAL(rowsRemoved(QModelIndex,int,int)), this, SLOT(checkCoinAddresses()));

    connect(getOptionsModel(), &OptionsModel::setReserveBalance, this, &WalletModel::setReserveBalance);
    connect(this, &WalletModel::notifyReservedBalanceChanged, getOptionsModel(), &OptionsModel::updateReservedBalance);

    subscribeToCoreSignals();
}

WalletModel::~WalletModel()
{
    unsubscribeFromCoreSignals();

    t.quit();
    t.wait();
}

void WalletModel::startPollBalance()
{
    // This timer will be fired repeatedly to update the balance
    connect(timer, &QTimer::timeout, this, &WalletModel::pollBalanceChanged);
    connect(timer, SIGNAL(timeout()), worker, SLOT(updateModel()));
    timer->start(MODEL_UPDATE_DELAY);
}

void WalletModel::setClientModel(ClientModel* client_model)
{
    m_client_model = client_model;
    if (!m_client_model) timer->stop();
}

void WalletModel::updateStatus()
{
    EncryptionStatus newEncryptionStatus = getEncryptionStatus();

    if(cachedEncryptionStatus != newEncryptionStatus) {
        Q_EMIT encryptionStatusChanged();
    }
}

void WalletModel::pollBalanceChanged()
{
    // Get node synchronization information
    int numBlocks = -1;
    bool isSyncing = false;
    pollNum++;
    if(!m_node.tryGetSyncInfo(numBlocks, isSyncing) || (isSyncing && pollNum < pollSyncSkip))
        return;

    // Avoid recomputing wallet balances unless a TransactionChanged or
    // BlockTip notification was received.
    if (!fForceCheckBalanceChanged && m_cached_last_update_tip == getLastBlockProcessed()) return;

    // Try to get balances and return early if locks can't be acquired. This
    // avoids the GUI from getting stuck on periodical polls if the core is
    // holding the locks for a longer time - for example, during a wallet
    // rescan.
    interfaces::WalletBalances new_balances;
    uint256 block_hash;
    if (!m_wallet->tryGetBalances(new_balances, block_hash)) {
        return;
    }
<<<<<<< HEAD
    if (fForceCheckBalanceChanged || block_hash != m_cached_last_update_tip) {
=======
    pollNum = 0;

    bool cachedBlockHashChanged = block_hash != m_cached_last_update_tip;
    if (fForceCheckBalanceChanged || cachedBlockHashChanged) {
>>>>>>> project-a/time/qtumcore0.21
        fForceCheckBalanceChanged = false;

        // Balance and number of transactions might have changed
        m_cached_last_update_tip = block_hash;

        bool balanceChanged = checkBalanceChanged(new_balances);
        if(transactionTableModel)
            transactionTableModel->updateConfirmations();

        if(tokenTransactionTableModel)
            tokenTransactionTableModel->updateConfirmations();

        if(cachedBlockHashChanged)
        {
            checkTokenBalanceChanged();
            checkDelegationChanged();
            checkSuperStakerChanged();
        }

        if(balanceChanged)
        {
            updateCoinAddresses = true;
        }

        // The stake weight is used for the staking icon status
        // Get the stake weight only when not syncing because it is time consuming
        if(!isSyncing && (balanceChanged || cachedBlockHashChanged))
        {
            updateStakeWeight = true;
        }
    }
}
void WalletModel::updateContractBook(const QString &address, const QString &label, const QString &abi, int status)
{
    if(contractTableModel)
        contractTableModel->updateEntry(address, label, abi, status);
}

<<<<<<< HEAD
void WalletModel::setReserveBalance(CAmount nReserveBalanceNew)
{
    m_wallet->setReserveBalance(nReserveBalanceNew);
};

void WalletModel::updateReservedBalanceChanged(CAmount nValue)
{
    Q_EMIT notifyReservedBalanceChanged(nValue);
};

void WalletModel::startRescan()
{
    std::thread t(CallRPCVoid, "rescanblockchain 0", util::Ref{m_node}, m_wallet->getWalletName(), true);
    t.detach();
};

void WalletModel::checkBalanceChanged(const interfaces::WalletBalances& new_balances)
=======
bool WalletModel::checkBalanceChanged(const interfaces::WalletBalances& new_balances)
>>>>>>> project-a/time/qtumcore0.21
{
    if(new_balances.balanceChanged(m_cached_balances)) {
        bool fHaveWatchOnlyCheck = new_balances.watch_only_balance || new_balances.unconfirmed_watch_only_balance || new_balances.balanceWatchStaked;
        if (fHaveWatchOnlyCheck != fHaveWatchOnly)
            updateWatchOnlyFlag(fHaveWatchOnlyCheck);
        m_cached_balances = new_balances;
        Q_EMIT balanceChanged(new_balances);
        return true;
    }
    return false;
}

void WalletModel::checkTokenBalanceChanged()
{
    if(tokenItemModel)
    {
        tokenItemModel->checkTokenBalanceChanged();
    }
}

void WalletModel::checkDelegationChanged()
{
    if(delegationItemModel)
    {
        delegationItemModel->checkDelegationChanged();
    }
}

void WalletModel::checkSuperStakerChanged()
{
    if(superStakerItemModel)
    {
        superStakerItemModel->checkSuperStakerChanged();
    }
}

void WalletModel::updateTransaction()
{
    // Balance and number of transactions might have changed
    fForceCheckBalanceChanged = true;
}

void WalletModel::updateAddressBook(const QString &address, const QString &label,
        bool isMine, const QString &purpose, const QString &path, int status)
{
    if(addressTableModel)
        addressTableModel->updateEntry(address, label, isMine, purpose, path, status);
}

void WalletModel::updateWatchOnlyFlag(bool fHaveWatchonly)
{
    fHaveWatchOnly = fHaveWatchonly;
    Q_EMIT notifyWatchonlyChanged(fHaveWatchonly);
}

bool WalletModel::validateAddress(const QString &address, bool allow_stakeonly)
{
    return IsValidDestinationString(address.toStdString(), allow_stakeonly);
}

WalletModel::SendCoinsReturn WalletModel::prepareTransaction(WalletModelTransaction &transaction, const CCoinControl& coinControl)
{
    CAmount total = 0;
    QList<SendCoinsRecipient> recipients = transaction.getRecipients();
    std::vector<CRecipient> vecSend;

    if(recipients.empty())
    {
        return OK;
    }

    QSet<QString> setAddress; // Used to detect duplicates
    int nAddresses = 0;

    // Pre-check input data for validity
    for (const SendCoinsRecipient &rcp : recipients)
    {
        // User-entered bitcoin address / amount:
        if (rcp.m_coldstake) {
            if (!validateAddress(rcp.spend_address) || !validateAddress(rcp.stake_address, true)) {
                return InvalidAddress;
            }
            if(rcp.amount <= 0) {
                return InvalidAmount;
            }
            //setAddress.insert(rcp.address);
            //++nAddresses;

            CScript scriptPubKey = GetScriptForDestination(DecodeDestination(rcp.address.toStdString()));
            CRecipient recipient = {scriptPubKey, rcp.amount, rcp.fSubtractFeeFromAmount};
            vecSend.push_back(recipient);

            total += rcp.amount;
            continue;
        }

        if(!validateAddress(rcp.address))
        {
            return InvalidAddress;
        }
        if(rcp.amount <= 0)
        {
            return InvalidAmount;
        }
        setAddress.insert(rcp.address);
        ++nAddresses;

        CScript scriptPubKey = GetScriptForDestination(DecodeDestination(rcp.address.toStdString()));
        CRecipient recipient = {scriptPubKey, rcp.amount, rcp.fSubtractFeeFromAmount};
        vecSend.push_back(recipient);

        total += rcp.amount;
    }
    if(setAddress.size() != nAddresses)
    {
        return DuplicateAddress;
    }

    /*
    CAmount nBalance = m_wallet->getAvailableBalance(coinControl);

    if(total > nBalance)
    {
        return AmountExceedsBalance;
    }


    {
        CAmount nFeeRequired = 0;
        int nChangePosRet = -1;
        bilingual_str error;

        auto& newTx = transaction.getWtx();
        newTx = m_wallet->createTransaction(vecSend, coinControl, !wallet().privateKeysDisabled() / sign /, nChangePosRet, nFeeRequired, error);
        transaction.setTransactionFee(nFeeRequired);
        if (fSubtractFeeFromAmount && newTx)
            transaction.reassignAmounts(nChangePosRet);

        if(!newTx)
        {
            if(!fSubtractFeeFromAmount && (total + nFeeRequired) > nBalance)
            {
                return SendCoinsReturn(AmountWithFeeExceedsBalance);
            }
            Q_EMIT message(tr("Send Coins"), QString::fromStdString(error.translated),
                CClientUIInterface::MSG_ERROR);
            return TransactionCreationFailed;
        }

        // Reject absurdly high fee. (This can never happen because the
        // wallet never creates transactions with fee greater than
        // m_default_max_tx_fee. This merely a belt-and-suspenders check).
        if (nFeeRequired > m_wallet->getDefaultMaxTxFee()) {
            return AbsurdFee;
        }
    }
    */
    return SendCoinsReturn(OK);
}

WalletModel::SendCoinsReturn WalletModel::sendCoins(WalletModelTransaction &transaction)
{
    QByteArray transaction_array; /* store serialized transaction */

    {
        std::vector<std::pair<std::string, std::string>> vOrderForm;
        for (const SendCoinsRecipient &rcp : transaction.getRecipients())
        {
            if (!rcp.message.isEmpty()) // Message from normal bitcoin:URI (bitcoin:123...?message=example)
                vOrderForm.emplace_back("Message", rcp.message.toStdString());
        }

        auto& newTx = transaction.getWtx();
        wallet().commitTransaction(newTx, {} /* mapValue */, std::move(vOrderForm));

        CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
        ssTx << *newTx;
        transaction_array.append(&(ssTx[0]), ssTx.size());
    }

    // Add addresses / update labels that we've sent to the address book,
    // and emit coinsSent signal for each recipient
    for (const SendCoinsRecipient &rcp : transaction.getRecipients())
    {
        {
            std::string strAddress = rcp.address.toStdString();
            CTxDestination dest = DecodeDestination(strAddress);
            std::string strLabel = rcp.label.toStdString();
            {
                // Check if we have a new address or an updated label
                std::string name;
                if (!m_wallet->getAddress(
                     dest, &name, /* is_mine= */ nullptr, /* purpose= */ nullptr))
                {
                    m_wallet->setAddressBook(dest, strLabel, "send");
                }
                else if (name != strLabel)
                {
                    m_wallet->setAddressBook(dest, strLabel, ""); // "" means don't change purpose
                }
            }
        }
        Q_EMIT coinsSent(this, rcp, transaction_array);
    }

    checkBalanceChanged(m_wallet->getBalances()); // update balance immediately, otherwise there could be a short noticeable delay until pollBalanceChanged hits

    return SendCoinsReturn(OK);
}

OptionsModel *WalletModel::getOptionsModel()
{
    return optionsModel;
}

AddressTableModel *WalletModel::getAddressTableModel()
{
    return addressTableModel;
}

ContractTableModel *WalletModel::getContractTableModel()
{
    return contractTableModel;
}

TransactionTableModel *WalletModel::getTransactionTableModel()
{
    return transactionTableModel;
}

RecentRequestsTableModel *WalletModel::getRecentRequestsTableModel()
{
    return recentRequestsTableModel;
}

TokenItemModel *WalletModel::getTokenItemModel()
{
    return tokenItemModel;
}

TokenTransactionTableModel *WalletModel::getTokenTransactionTableModel()
{
    return tokenTransactionTableModel;
}

DelegationItemModel *WalletModel::getDelegationItemModel()
{
    return delegationItemModel;
}

SuperStakerItemModel *WalletModel::getSuperStakerItemModel()
{
    return superStakerItemModel;
}

DelegationStakerItemModel *WalletModel::getDelegationStakerItemModel()
{
    return delegationStakerItemModel;
}

WalletModel::EncryptionStatus WalletModel::getEncryptionStatus() const
{
    if(!m_wallet->isCrypted())
    {
        return Unencrypted;
    }
    else if(m_wallet->isLocked())
    {
        return Locked;
    }
    else
    {
        if (m_wallet->isUnlockForStakingOnlySet())
            return UnlockedForStaking;

        return Unlocked;
    }
}

bool WalletModel::setWalletEncrypted(bool encrypted, const SecureString &passphrase)
{
    if (encrypted) {
        return m_wallet->encryptWallet(passphrase);
    }
    return false;
}

bool WalletModel::setWalletLocked(bool locked, const SecureString &passPhrase, bool stakingOnly)
{
    if(locked)
    {
        // Lock
        return m_wallet->lock();
    }
    else
    {
        // Unlock
        return m_wallet->unlock(passPhrase, stakingOnly);
    }
}

bool WalletModel::setUnlockedForStaking()
{
    if (!m_wallet->setUnlockedForStaking())
        return false;
    updateStatus();
    return true;
}

bool WalletModel::changePassphrase(const SecureString &oldPass, const SecureString &newPass)
{
    m_wallet->lock(); // Make sure wallet is locked before attempting pass change
    return m_wallet->changeWalletPassphrase(oldPass, newPass);
}

bool WalletModel::restoreWallet(const QString &filename, const QString &param)
{
    if(QFile::exists(filename))
    {
        fs::path pathWalletBak = GetDataDir() / strprintf("wallet.%d.bak", GetTime());
        std::string walletBak = pathWalletBak.string();
        if(m_wallet->backupWallet(walletBak))
        {
            restorePath = filename;
            restoreParam = param;
            return true;
        }
    }

    return false;
}

// Handlers for core signals
static void NotifyUnload(WalletModel* walletModel)
{
    qDebug() << "NotifyUnload";
    bool invoked = QMetaObject::invokeMethod(walletModel, "unload");
    assert(invoked);
}

static void NotifyKeyStoreStatusChanged(WalletModel *walletmodel)
{
    qDebug() << "NotifyKeyStoreStatusChanged";
    bool invoked = QMetaObject::invokeMethod(walletmodel, "updateStatus", Qt::QueuedConnection);
    assert(invoked);
}

static void NotifyAddressBookChanged(WalletModel *walletmodel,
        const CTxDestination &address, const std::string &label, bool isMine,
        const std::string &purpose, const std::string &path, ChangeType status)
{
    QString strAddress = QString::fromStdString(EncodeDestination(address));
    QString strLabel = QString::fromStdString(label);
    QString strPurpose = QString::fromStdString(purpose);
    QString strPath = QString::fromStdString(path);

    qDebug() << "NotifyAddressBookChanged: " + strAddress + " " + strLabel + " isMine=" + QString::number(isMine) + " purpose=" + strPurpose + " status=" + QString::number(status);
    bool invoked = QMetaObject::invokeMethod(walletmodel, "updateAddressBook", Qt::QueuedConnection,
                              Q_ARG(QString, strAddress),
                              Q_ARG(QString, strLabel),
                              Q_ARG(bool, isMine),
                              Q_ARG(QString, strPurpose),
                              Q_ARG(QString, strPath),
                              Q_ARG(int, status));
    assert(invoked);
}

static void NotifyTransactionChanged(WalletModel *walletmodel, const uint256 &hash, ChangeType status)
{
    Q_UNUSED(hash);
    Q_UNUSED(status);
    bool invoked = QMetaObject::invokeMethod(walletmodel, "updateTransaction", Qt::QueuedConnection);
    assert(invoked);
}

static void ShowProgress(WalletModel *walletmodel, const std::string &title, int nProgress)
{
    // emits signal "showProgress"
    bool invoked = QMetaObject::invokeMethod(walletmodel, "showProgress", Qt::QueuedConnection,
                              Q_ARG(QString, QString::fromStdString(title)),
                              Q_ARG(int, nProgress));
    assert(invoked);
}

static void NotifyWatchonlyChanged(WalletModel *walletmodel, bool fHaveWatchonly)
{
    bool invoked = QMetaObject::invokeMethod(walletmodel, "updateWatchOnlyFlag", Qt::QueuedConnection,
                              Q_ARG(bool, fHaveWatchonly));
    assert(invoked);
}

static void NotifyCanGetAddressesChanged(WalletModel* walletmodel)
{
    bool invoked = QMetaObject::invokeMethod(walletmodel, "canGetAddressesChanged");
    assert(invoked);
}

<<<<<<< HEAD
static void NotifyReservedBalanceChanged(WalletModel *walletmodel, CAmount nValue)
{
    QMetaObject::invokeMethod(walletmodel, "updateReservedBalanceChanged", Qt::QueuedConnection,
                              Q_ARG(CAmount, nValue));
}

=======
static void NotifyContractBookChanged(WalletModel *walletmodel,
        const std::string &address, const std::string &label, const std::string &abi, ChangeType status)
{
    QString strAddress = QString::fromStdString(address);
    QString strLabel = QString::fromStdString(label);
    QString strAbi = QString::fromStdString(abi);

    qDebug() << "NotifyContractBookChanged: " + strAddress + " " + strLabel + " status=" + QString::number(status);
    bool invoked = QMetaObject::invokeMethod(walletmodel, "updateContractBook", Qt::QueuedConnection,
                              Q_ARG(QString, strAddress),
                              Q_ARG(QString, strLabel),
                              Q_ARG(QString, strAbi),
                              Q_ARG(int, status));
    assert(invoked);
}
>>>>>>> project-a/time/qtumcore0.21

void WalletModel::subscribeToCoreSignals()
{
    // Connect signals to wallet
    m_handler_unload = m_wallet->handleUnload(std::bind(&NotifyUnload, this));
    m_handler_status_changed = m_wallet->handleStatusChanged(std::bind(&NotifyKeyStoreStatusChanged, this));
    m_handler_address_book_changed = m_wallet->handleAddressBookChanged(std::bind(NotifyAddressBookChanged, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6));
    m_handler_transaction_changed = m_wallet->handleTransactionChanged(std::bind(NotifyTransactionChanged, this, std::placeholders::_1, std::placeholders::_2));
    m_handler_show_progress = m_wallet->handleShowProgress(std::bind(ShowProgress, this, std::placeholders::_1, std::placeholders::_2));
    m_handler_watch_only_changed = m_wallet->handleWatchOnlyChanged(std::bind(NotifyWatchonlyChanged, this, std::placeholders::_1));
    m_handler_can_get_addrs_changed = m_wallet->handleCanGetAddressesChanged(std::bind(NotifyCanGetAddressesChanged, this));
<<<<<<< HEAD

    if (m_wallet->IsParticlWallet()) {
        m_handler_reserved_balance_changed = m_wallet->handleReservedBalanceChanged(std::bind(NotifyReservedBalanceChanged, this, std::placeholders::_1));
    }
=======
    m_handler_contract_book_changed = m_wallet->handleContractBookChanged(std::bind(NotifyContractBookChanged, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4));
>>>>>>> project-a/time/qtumcore0.21
}

void WalletModel::unsubscribeFromCoreSignals()
{
    // Disconnect signals from wallet
    m_handler_unload->disconnect();
    m_handler_status_changed->disconnect();
    m_handler_address_book_changed->disconnect();
    m_handler_transaction_changed->disconnect();
    m_handler_show_progress->disconnect();
    m_handler_watch_only_changed->disconnect();
    m_handler_can_get_addrs_changed->disconnect();
<<<<<<< HEAD

    if (m_wallet->IsParticlWallet()) {
        m_handler_reserved_balance_changed->disconnect();
    }
=======
    m_handler_contract_book_changed->disconnect();
>>>>>>> project-a/time/qtumcore0.21
}

// WalletModel::UnlockContext implementation
WalletModel::UnlockContext WalletModel::requestUnlock()
{
<<<<<<< HEAD
    bool was_locked = getEncryptionStatus() == Locked || getEncryptionStatus() == UnlockedForStaking;
    bool was_unlocked_for_staking = getEncryptionStatus() == UnlockedForStaking;
=======
    bool was_locked = getEncryptionStatus() == Locked;

    if ((!was_locked) && getWalletUnlockStakingOnly())
    {
       setWalletLocked(true);
       was_locked = getEncryptionStatus() == Locked;
    }

>>>>>>> project-a/time/qtumcore0.21
    if(was_locked)
    {
        // Request UI to unlock wallet
        Q_EMIT requireUnlock();
    }
    // If wallet is still locked, unlock was failed or cancelled, mark context as invalid
    //bool valid = getEncryptionStatus() != Locked;
    EncryptionStatus newStatus = getEncryptionStatus();
    bool valid = newStatus == Unlocked || newStatus == Unencrypted;

<<<<<<< HEAD
    return UnlockContext(this, valid, was_locked, was_unlocked_for_staking);
=======
    return UnlockContext(this, valid, was_locked && !getWalletUnlockStakingOnly());
>>>>>>> project-a/time/qtumcore0.21
}

WalletModel::UnlockContext::UnlockContext(WalletModel *_wallet, bool _valid, bool _relock, bool _was_unlocked_for_staking):
        wallet(_wallet),
        valid(_valid),
        relock(_relock),
<<<<<<< HEAD
        was_unlocked_for_staking(_was_unlocked_for_staking)
=======
        stakingOnly(false)
>>>>>>> project-a/time/qtumcore0.21
{
    if(!relock)
    {
        stakingOnly = wallet->getWalletUnlockStakingOnly();
        wallet->setWalletUnlockStakingOnly(false);
    }
}

WalletModel::UnlockContext::~UnlockContext()
{
    if (valid && relock) {
        if (was_unlocked_for_staking) {
            wallet->setUnlockedForStaking();
        } else {
            wallet->setWalletLocked(true);
        }
    }

    if(!relock)
    {
        wallet->setWalletUnlockStakingOnly(stakingOnly);
        wallet->updateStatus();
    }
}

void WalletModel::UnlockContext::CopyFrom(UnlockContext&& rhs)
{
    // Transfer context; old object no longer relocks wallet
    *this = rhs;
    rhs.relock = false;
}

bool WalletModel::isHardwareLinkedWallet() const {
    return m_wallet->isHardwareLinkedWallet();
}

bool WalletModel::tryCallRpc(const QString &sCommand, UniValue &rv, bool returnError) const
{
    try {
        util::Ref context{m_node};
        rv = CallRPC(sCommand.toStdString(), context, m_wallet->getWalletName(), true);
    } catch (UniValue& objError) {
        if (returnError) {
            rv = objError;
            return false;
        }
        try { // Nice formatting for standard-format error
            int code = find_value(objError, "code").get_int();
            std::string message = find_value(objError, "message").get_str();
            warningBox(tr("Wallet Model"), QString::fromStdString(message) + " (code " + QString::number(code) + ")");
            return false;
        } catch (const std::runtime_error&) { // raised when converting to invalid type, i.e. missing code or message
            // Show raw JSON object
            warningBox(tr("Wallet Model"), QString::fromStdString(objError.write()));
            return false;
        }
    } catch (const std::exception& e) {
        if (returnError) {
            rv = UniValue(UniValue::VOBJ);
            rv.pushKV("Error", e.what());
        } else {
            warningBox(tr("Wallet Model"), QString::fromStdString(e.what()));
        }
        return false;
    }

    return true;
};

void WalletModel::warningBox(QString heading, QString msg) const
{
    qWarning() << msg;
    QPair<QString, CClientUIInterface::MessageBoxFlags> msgParams;
    msgParams.second = CClientUIInterface::MSG_WARNING;
    msgParams.first = msg;

    Q_EMIT message(heading, msgParams.first, msgParams.second);
};

void WalletModel::loadReceiveRequests(std::vector<std::string>& vReceiveRequests)
{
    vReceiveRequests = m_wallet->getDestValues("rr"); // receive request
}

bool WalletModel::saveReceiveRequest(const std::string &sAddress, const int64_t nId, const std::string &sRequest)
{
    CTxDestination dest = DecodeDestination(sAddress);

    std::stringstream ss;
    ss << nId;
    std::string key = "rr" + ss.str(); // "rr" prefix = "receive request" in destdata

    if (sRequest.empty())
        return m_wallet->eraseDestData(dest, key);
    else
        return m_wallet->addDestData(dest, key, sRequest);
}

bool WalletModel::bumpFee(uint256 hash, uint256& new_hash)
{
    CCoinControl coin_control;
    coin_control.m_signal_bip125_rbf = true;
    std::vector<bilingual_str> errors;
    CAmount old_fee;
    CAmount new_fee;
    CMutableTransaction mtx;
    if (!m_wallet->createBumpTransaction(hash, coin_control, errors, old_fee, new_fee, mtx)) {
        QMessageBox::critical(nullptr, tr("Fee bump error"), tr("Increasing transaction fee failed") + "<br />(" +
            (errors.size() ? QString::fromStdString(errors[0].translated) : "") +")");
        return false;
    }

    const bool create_psbt = m_wallet->privateKeysDisabled();

    // allow a user based fee verification
    QString questionString = create_psbt ? tr("Do you want to draft a transaction with fee increase?") : tr("Do you want to increase the fee?");
    questionString.append("<br />");
    questionString.append("<table style=\"text-align: left;\">");
    questionString.append("<tr><td>");
    questionString.append(tr("Current fee:"));
    questionString.append("</td><td>");
    questionString.append(BitcoinUnits::formatHtmlWithUnit(getOptionsModel()->getDisplayUnit(), old_fee));
    questionString.append("</td></tr><tr><td>");
    questionString.append(tr("Increase:"));
    questionString.append("</td><td>");
    questionString.append(BitcoinUnits::formatHtmlWithUnit(getOptionsModel()->getDisplayUnit(), new_fee - old_fee));
    questionString.append("</td></tr><tr><td>");
    questionString.append(tr("New fee:"));
    questionString.append("</td><td>");
    questionString.append(BitcoinUnits::formatHtmlWithUnit(getOptionsModel()->getDisplayUnit(), new_fee));
    questionString.append("</td></tr></table>");
    SendConfirmationDialog confirmationDialog(tr("Confirm fee bump"), questionString);
    confirmationDialog.exec();
    QMessageBox::StandardButton retval = static_cast<QMessageBox::StandardButton>(confirmationDialog.result());

    // cancel sign&broadcast if user doesn't want to bump the fee
    if (retval != QMessageBox::Yes) {
        return false;
    }

    WalletModel::UnlockContext ctx(requestUnlock());
    if(!ctx.isValid())
    {
        return false;
    }

    // Short-circuit if we are returning a bumped transaction PSBT to clipboard
    if (create_psbt) {
        PartiallySignedTransaction psbtx(mtx);
        bool complete = false;
        const TransactionError err = wallet().fillPSBT(SIGHASH_ALL, false /* sign */, true /* bip32derivs */, psbtx, complete, nullptr);
        if (err != TransactionError::OK || complete) {
            QMessageBox::critical(nullptr, tr("Fee bump error"), tr("Can't draft transaction."));
            return false;
        }
        // Serialize the PSBT
        CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
        ssTx << psbtx;
        GUIUtil::setClipboard(EncodeBase64(ssTx.str()).c_str());
        Q_EMIT message(tr("PSBT copied"), "Copied to clipboard", CClientUIInterface::MSG_INFORMATION);
        return true;
    }

    // sign bumped transaction
    if (!m_wallet->signBumpTransaction(mtx)) {
        QMessageBox::critical(nullptr, tr("Fee bump error"), tr("Can't sign transaction."));
        return false;
    }
    // commit the bumped transaction
    if(!m_wallet->commitBumpTransaction(hash, std::move(mtx), errors, new_hash)) {
        QMessageBox::critical(nullptr, tr("Fee bump error"), tr("Could not commit transaction") + "<br />(" +
            QString::fromStdString(errors[0].translated)+")");
        return false;
    }
    return true;
}

bool WalletModel::isWalletEnabled()
{
   return !gArgs.GetBoolArg("-disablewallet", DEFAULT_DISABLE_WALLET);
}

void WalletModel::lockWallet()
{
    m_wallet->lockWallet();
}

QString WalletModel::getWalletName() const
{
    return QString::fromStdString(m_wallet->getWalletName());
}

QString WalletModel::getDisplayName() const
{
    const QString name = getWalletName();
    return name.isEmpty() ? "["+tr("default wallet")+"]" : name;
}

bool WalletModel::isMultiwallet()
{
    return m_node.walletClient().getWallets().size() > 1;
}

void WalletModel::refresh(bool pk_hash_only)
{
    addressTableModel = new AddressTableModel(this, pk_hash_only);
}

uint256 WalletModel::getLastBlockProcessed() const
{
    return m_client_model ? m_client_model->getBestBlockHash() : uint256{};
}

QString WalletModel::getRestorePath()
{
    return restorePath;
}

QString WalletModel::getRestoreParam()
{
    return restoreParam;
}

bool WalletModel::restore()
{
    return !restorePath.isEmpty();
}

uint64_t WalletModel::getStakeWeight()
{
    return nWeight;
}

bool WalletModel::getWalletUnlockStakingOnly()
{
    return m_wallet->getWalletUnlockStakingOnly();
}

void WalletModel::setWalletUnlockStakingOnly(bool unlock)
{
    m_wallet->setWalletUnlockStakingOnly(unlock);
}

void WalletModel::checkCoinAddressesChanged()
{
    // Get the list of coin addresses and emit it to the subscribers
    std::vector<std::string> spendableAddresses;
    std::vector<std::string> allAddresses;
    bool includeZeroValue = false;
    if(updateCoinAddresses && m_wallet->tryGetAvailableAddresses(spendableAddresses, allAddresses, includeZeroValue))
    {
        QStringList listSpendableAddresses;
        for(std::string address : spendableAddresses)
            listSpendableAddresses.append(QString::fromStdString(address));

        QStringList listAllAddresses;
        for(std::string address : allAddresses)
            listAllAddresses.append(QString::fromStdString(address));

        Q_EMIT availableAddressesChanged(listSpendableAddresses, listAllAddresses, includeZeroValue);

        updateCoinAddresses = false;
    }
}

void WalletModel::checkStakeWeightChanged()
{
    if(updateStakeWeight && m_wallet->tryGetStakeWeight(nWeight))
    {
        updateStakeWeight = false;
    }
}

void WalletModel::checkCoinAddresses()
{
    updateCoinAddresses = true;
}
