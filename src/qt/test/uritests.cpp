// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/uritests.h>

#include <qt/guiutil.h>
#include <qt/walletmodel.h>

#include <QUrl>

void URITests::uriTests()
{
    SendCoinsRecipient rv;
    QUrl uri;
<<<<<<< HEAD
    uri.setUrl(QString("particl:Pe1feuHG57PBB35uwSkhoxVCkfHSPULGPN?req-dontexist="));
    QVERIFY(!GUIUtil::parseBitcoinURI(uri, &rv));

    uri.setUrl(QString("particl:Pe1feuHG57PBB35uwSkhoxVCkfHSPULGPN?dontexist="));
=======
    uri.setUrl(QString("qtum:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?req-dontexist="));
    QVERIFY(!GUIUtil::parseBitcoinURI(uri, &rv));

    uri.setUrl(QString("qtum:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?dontexist="));
>>>>>>> project-a/time/qtumcore0.21
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("Pe1feuHG57PBB35uwSkhoxVCkfHSPULGPN"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 0);

<<<<<<< HEAD
    uri.setUrl(QString("particl:Pe1feuHG57PBB35uwSkhoxVCkfHSPULGPN?label=Wikipedia Example Address"));
=======
    uri.setUrl(QString("qtum:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?label=Wikipedia Example Address"));
>>>>>>> project-a/time/qtumcore0.21
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("Pe1feuHG57PBB35uwSkhoxVCkfHSPULGPN"));
    QVERIFY(rv.label == QString("Wikipedia Example Address"));
    QVERIFY(rv.amount == 0);

<<<<<<< HEAD
    uri.setUrl(QString("particl:Pe1feuHG57PBB35uwSkhoxVCkfHSPULGPN?amount=0.001"));
=======
    uri.setUrl(QString("qtum:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=0.001"));
>>>>>>> project-a/time/qtumcore0.21
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("Pe1feuHG57PBB35uwSkhoxVCkfHSPULGPN"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 100000);

<<<<<<< HEAD
    uri.setUrl(QString("particl:Pe1feuHG57PBB35uwSkhoxVCkfHSPULGPN?amount=1.001"));
=======
    uri.setUrl(QString("qtum:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=1.001"));
>>>>>>> project-a/time/qtumcore0.21
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("Pe1feuHG57PBB35uwSkhoxVCkfHSPULGPN"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 100100000);

<<<<<<< HEAD
    uri.setUrl(QString("particl:Pe1feuHG57PBB35uwSkhoxVCkfHSPULGPN?amount=100&label=Wikipedia Example"));
=======
    uri.setUrl(QString("qtum:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=100&label=Wikipedia Example"));
>>>>>>> project-a/time/qtumcore0.21
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("Pe1feuHG57PBB35uwSkhoxVCkfHSPULGPN"));
    QVERIFY(rv.amount == 10000000000LL);
    QVERIFY(rv.label == QString("Wikipedia Example"));

<<<<<<< HEAD
    uri.setUrl(QString("particl:Pe1feuHG57PBB35uwSkhoxVCkfHSPULGPN?message=Wikipedia Example Address"));
=======
    uri.setUrl(QString("qtum:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?message=Wikipedia Example Address"));
>>>>>>> project-a/time/qtumcore0.21
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("Pe1feuHG57PBB35uwSkhoxVCkfHSPULGPN"));
    QVERIFY(rv.label == QString());

<<<<<<< HEAD
    QVERIFY(GUIUtil::parseBitcoinURI("particl:Pe1feuHG57PBB35uwSkhoxVCkfHSPULGPN?message=Wikipedia Example Address", &rv));
    QVERIFY(rv.address == QString("Pe1feuHG57PBB35uwSkhoxVCkfHSPULGPN"));
    QVERIFY(rv.label == QString());

    uri.setUrl(QString("particl:Pe1feuHG57PBB35uwSkhoxVCkfHSPULGPN?req-message=Wikipedia Example Address"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));

    uri.setUrl(QString("particl:Pe1feuHG57PBB35uwSkhoxVCkfHSPULGPN?amount=1,000&label=Wikipedia Example"));
    QVERIFY(!GUIUtil::parseBitcoinURI(uri, &rv));

    uri.setUrl(QString("particl:Pe1feuHG57PBB35uwSkhoxVCkfHSPULGPN?amount=1,000.0&label=Wikipedia Example"));
=======
    QVERIFY(GUIUtil::parseBitcoinURI("qtum:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?message=Wikipedia Example Address", &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.label == QString());

    uri.setUrl(QString("qtum:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?req-message=Wikipedia Example Address"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));

    uri.setUrl(QString("qtum:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=1,000&label=Wikipedia Example"));
    QVERIFY(!GUIUtil::parseBitcoinURI(uri, &rv));

    uri.setUrl(QString("qtum:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=1,000.0&label=Wikipedia Example"));
>>>>>>> project-a/time/qtumcore0.21
    QVERIFY(!GUIUtil::parseBitcoinURI(uri, &rv));
}
