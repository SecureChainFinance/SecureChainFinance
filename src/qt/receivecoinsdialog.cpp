// Copyright (c) 2011-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/wallet.h>

#include <qt/receivecoinsdialog.h>
#include <qt/forms/ui_receivecoinsdialog.h>

#include <interfaces/node.h>
#include <qt/addresstablemodel.h>
#include <qt/optionsmodel.h>
#include <qt/platformstyle.h>
#include <qt/recentrequeststablemodel.h>
#include <qt/walletmodel.h>
#include <qt/styleSheet.h>

#include <QAction>
#include <QCursor>
#include <QMessageBox>
#include <QScrollBar>
#include <QTextDocument>

ReceiveCoinsDialog::ReceiveCoinsDialog(const PlatformStyle *_platformStyle, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ReceiveCoinsDialog),
    columnResizingFixer(nullptr),
    model(nullptr),
    platformStyle(_platformStyle)
{
    ui->setupUi(this);

    // Set stylesheet
    SetObjectStyleSheet(ui->showRequestButton, StyleSheetNames::ButtonTransparentBordered);
    SetObjectStyleSheet(ui->removeRequestButton, StyleSheetNames::ButtonTransparentBordered);

    if (!_platformStyle->getImagesOnButtons()) {
        ui->showRequestButton->setIcon(QIcon());
        ui->removeRequestButton->setIcon(QIcon());
    } else {
        ui->showRequestButton->setIcon(_platformStyle->MultiStatesIcon(":/icons/show", PlatformStyle::PushButton));
        ui->removeRequestButton->setIcon(_platformStyle->MultiStatesIcon(":/icons/remove", PlatformStyle::PushButton));
    }

    // context menu actions
    QAction *copyURIAction = new QAction(tr("Copy URI"), this);
    QAction *copyLabelAction = new QAction(tr("Copy label"), this);
    QAction *copyMessageAction = new QAction(tr("Copy message"), this);
    QAction *copyAmountAction = new QAction(tr("Copy amount"), this);

    // context menu
    contextMenu = new QMenu(this);
    contextMenu->addAction(copyURIAction);
    contextMenu->addAction(copyLabelAction);
    contextMenu->addAction(copyMessageAction);
    contextMenu->addAction(copyAmountAction);

    // context menu signals
    connect(ui->recentRequestsView, &QWidget::customContextMenuRequested, this, &ReceiveCoinsDialog::showMenu);
    connect(copyURIAction, &QAction::triggered, this, &ReceiveCoinsDialog::copyURI);
    connect(copyLabelAction, &QAction::triggered, this, &ReceiveCoinsDialog::copyLabel);
    connect(copyMessageAction, &QAction::triggered, this, &ReceiveCoinsDialog::copyMessage);
    connect(copyAmountAction, &QAction::triggered, this, &ReceiveCoinsDialog::copyAmount);

}

void ReceiveCoinsDialog::setModel(WalletModel *_model)
{
    this->model = _model;

    if(_model && _model->getOptionsModel())
    {
        _model->getRecentRequestsTableModel()->sort(RecentRequestsTableModel::Date, Qt::DescendingOrder);
        connect(_model->getOptionsModel(), &OptionsModel::displayUnitChanged, this, &ReceiveCoinsDialog::updateDisplayUnit);
        updateDisplayUnit();

        QTableView* tableView = ui->recentRequestsView;

        tableView->verticalHeader()->hide();
        tableView->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        tableView->setModel(_model->getRecentRequestsTableModel());
        tableView->setAlternatingRowColors(true);
        tableView->setSelectionBehavior(QAbstractItemView::SelectRows);
        tableView->setSelectionMode(QAbstractItemView::ContiguousSelection);
        tableView->setColumnWidth(RecentRequestsTableModel::Date, DATE_COLUMN_WIDTH);
        tableView->setColumnWidth(RecentRequestsTableModel::Label, LABEL_COLUMN_WIDTH);
        tableView->setColumnWidth(RecentRequestsTableModel::Amount, AMOUNT_MINIMUM_COLUMN_WIDTH);

        connect(tableView->selectionModel(),
            &QItemSelectionModel::selectionChanged, this,
            &ReceiveCoinsDialog::recentRequestsView_selectionChanged);
        // Last 2 columns are set by the columnResizingFixer, when the table geometry is ready.
        columnResizingFixer = new GUIUtil::TableViewLastColumnResizingFixer(tableView, AMOUNT_MINIMUM_COLUMN_WIDTH, DATE_COLUMN_WIDTH, this);

        if (model->node().isAddressTypeSet()) {
            // user explicitly set the type, use it
            if (model->wallet().getDefaultAddressType() == OutputType::BECH32) {
                ui->useBech32->setCheckState(Qt::Checked);
            } else {
                ui->useBech32->setCheckState(Qt::Unchecked);
            }
        } else {
            // Always fall back to default in the gui
            ui->useBech32->setVisible(model->wallet().getDefaultAddressType() != OutputType::LEGACY);
        }

        // Set the button to be enabled or disabled based on whether the wallet can give out new addresses.
        ui->receiveButton->setEnabled(model->wallet().canGetAddresses());

        // Enable/disable the receive button if the wallet is now able/unable to give out new addresses.
        connect(model, &WalletModel::canGetAddressesChanged, [this] {
            ui->receiveButton->setEnabled(model->wallet().canGetAddresses());
        });
    }
}

ReceiveCoinsDialog::~ReceiveCoinsDialog()
{
    delete ui;
}

void ReceiveCoinsDialog::clear()
{
    ui->reqAmount->clear();
    ui->reqLabel->setText("");
    ui->reqMessage->setText("");
    ui->cbxAddressType->setCurrentIndex(ui->cbxAddressType->findText("Standard"));
    updateDisplayUnit();
}

void ReceiveCoinsDialog::reject()
{
    clear();
    QDialog::reject();
}

void ReceiveCoinsDialog::accept()
{
    clear();
    QDialog::accept();
}

void ReceiveCoinsDialog::updateDisplayUnit()
{
    if(model && model->getOptionsModel())
    {
        ui->reqAmount->setDisplayUnit(model->getOptionsModel()->getDisplayUnit());
    }
}

void ReceiveCoinsDialog::on_receiveButton_clicked()
{
    if(!model || !model->getOptionsModel() || !model->getAddressTableModel() || !model->getRecentRequestsTableModel())
        return;

    QString address;
    QString label = ui->reqLabel->text();

    /* Generate new receiving address
    OutputType address_type;
    if (ui->useBech32->isChecked()) {
        address_type = OutputType::BECH32;
    } else {
        address_type = model->wallet().getDefaultAddressType();
        if (address_type == OutputType::BECH32) {
            address_type = OutputType::P2SH_SEGWIT;
        }
    }
    */
    OutputType address_type = ui->useBech32->isChecked() ? OutputType::BECH32 : OutputType::LEGACY;

    /* Generate new receiving address */
    AddressTableModel::AddrType addrType = AddressTableModel::ADDR_STANDARD;

    if (ui->cbxAddressType->currentText() == "Stealth")
        addrType = AddressTableModel::ADDR_STEALTH;
    else
    if (ui->cbxAddressType->currentText() == "Extended")
        addrType = AddressTableModel::ADDR_EXT;
    else
    if (ui->cbxAddressType->currentText() == "Standard 256bit")
        addrType = AddressTableModel::ADDR_STANDARD256;

    address = model->getAddressTableModel()->addRow(AddressTableModel::Receive, label, "", address_type, addrType);

    switch(model->getAddressTableModel()->getEditStatus())
    {
    case AddressTableModel::EditStatus::OK: {
        // Success
        SendCoinsRecipient _info(address, label,
            ui->reqAmount->value(), ui->reqMessage->text());

        /* Store request for later reference */
        model->getRecentRequestsTableModel()->addNewRequest(_info);
        info = _info;
        break;
    }
    case AddressTableModel::EditStatus::WALLET_UNLOCK_FAILURE:
        QMessageBox::critical(this, windowTitle(),
            tr("Could not unlock wallet."),
            QMessageBox::Ok, QMessageBox::Ok);
        break;
    case AddressTableModel::EditStatus::KEY_GENERATION_FAILURE:
        QMessageBox::critical(this, windowTitle(),
            tr("Could not generate new %1 address").arg(QString::fromStdString(FormatOutputType(address_type))),
            QMessageBox::Ok, QMessageBox::Ok);
        break;
    // These aren't valid return values for our action
    case AddressTableModel::EditStatus::INVALID_ADDRESS:
    case AddressTableModel::EditStatus::DUPLICATE_ADDRESS:
    case AddressTableModel::EditStatus::NO_CHANGES:
        assert(false);
    }
    clear();
    accept();
}

void ReceiveCoinsDialog::on_recentRequestsView_doubleClicked(const QModelIndex &index)
{
    const RecentRequestsTableModel *submodel = model->getRecentRequestsTableModel();
    info = submodel->entry(index.row()).recipient;

    accept();
}

void ReceiveCoinsDialog::on_recentRequestsView_clicked(const QModelIndex &index)
{
    const RecentRequestsTableModel *submodel = model->getRecentRequestsTableModel();
    SendCoinsRecipient info = submodel->entry(index.row()).recipient;

    ui->reqLabel->setText(info.label);
    ui->reqMessage->setText(info.message);
    ui->reqAmount->setValue(info.amount);
}

void ReceiveCoinsDialog::recentRequestsView_selectionChanged(const QItemSelection &selected, const QItemSelection &deselected)
{
    // Enable Show/Remove buttons only if anything is selected.
    bool enable = !ui->recentRequestsView->selectionModel()->selectedRows().isEmpty();
    ui->showRequestButton->setEnabled(enable);
    ui->removeRequestButton->setEnabled(enable);
}

void ReceiveCoinsDialog::on_showRequestButton_clicked()
{
    if(!model || !model->getRecentRequestsTableModel() || !ui->recentRequestsView->selectionModel())
        return;
    QModelIndexList selection = ui->recentRequestsView->selectionModel()->selectedRows();

    for (const QModelIndex& index : selection) {
        on_recentRequestsView_doubleClicked(index);
    }
}

void ReceiveCoinsDialog::on_removeRequestButton_clicked()
{
    if(!model || !model->getRecentRequestsTableModel() || !ui->recentRequestsView->selectionModel())
        return;
    QModelIndexList selection = ui->recentRequestsView->selectionModel()->selectedRows();
    if(selection.empty())
        return;
    // correct for selection mode ContiguousSelection
    QModelIndex firstIndex = selection.at(0);
    model->getRecentRequestsTableModel()->removeRows(firstIndex.row(), selection.length(), firstIndex.parent());
}

// We override the virtual resizeEvent of the QWidget to adjust tables column
// sizes as the tables width is proportional to the dialogs width.
void ReceiveCoinsDialog::resizeEvent(QResizeEvent *event)
{
    QWidget::resizeEvent(event);
    columnResizingFixer->stretchColumnWidth(RecentRequestsTableModel::Message);
}

QModelIndex ReceiveCoinsDialog::selectedRow()
{
    if(!model || !model->getRecentRequestsTableModel() || !ui->recentRequestsView->selectionModel())
        return QModelIndex();
    QModelIndexList selection = ui->recentRequestsView->selectionModel()->selectedRows();
    if(selection.empty())
        return QModelIndex();
    // correct for selection mode ContiguousSelection
    QModelIndex firstIndex = selection.at(0);
    return firstIndex;
}

// copy column of selected row to clipboard
void ReceiveCoinsDialog::copyColumnToClipboard(int column)
{
    QModelIndex firstIndex = selectedRow();
    if (!firstIndex.isValid()) {
        return;
    }
    GUIUtil::setClipboard(model->getRecentRequestsTableModel()->index(firstIndex.row(), column).data(Qt::EditRole).toString());
}

// context menu
void ReceiveCoinsDialog::showMenu(const QPoint &point)
{
    if (!selectedRow().isValid()) {
        return;
    }
    contextMenu->exec(QCursor::pos());
}

// context menu action: copy URI
void ReceiveCoinsDialog::copyURI()
{
    QModelIndex sel = selectedRow();
    if (!sel.isValid()) {
        return;
    }

    const RecentRequestsTableModel * const submodel = model->getRecentRequestsTableModel();
    const QString uri = GUIUtil::formatBitcoinURI(submodel->entry(sel.row()).recipient);
    GUIUtil::setClipboard(uri);
}

// context menu action: copy label
void ReceiveCoinsDialog::copyLabel()
{
    copyColumnToClipboard(RecentRequestsTableModel::Label);
}

// context menu action: copy message
void ReceiveCoinsDialog::copyMessage()
{
    copyColumnToClipboard(RecentRequestsTableModel::Message);
}

// context menu action: copy amount
void ReceiveCoinsDialog::copyAmount()
{
    copyColumnToClipboard(RecentRequestsTableModel::Amount);
}

SendCoinsRecipient ReceiveCoinsDialog::getInfo() const
{
    return info;
}

void ReceiveCoinsDialog::on_cancelButton_clicked()
{
    reject();
}
