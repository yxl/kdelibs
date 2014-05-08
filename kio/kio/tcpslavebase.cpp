/*
 * Copyright (C) 2000 Alex Zepeda <zipzippy@sonic.net>
 * Copyright (C) 2001-2003 George Staikos <staikos@kde.org>
 * Copyright (C) 2001 Dawit Alemayehu <adawit@kde.org>
 * Copyright (C) 2007,2008 Andreas Hartmetz <ahartmetz@gmail.com>
 * Copyright (C) 2008 Roland Harnau <tau@gmx.eu>
 * Copyright (C) 2010 Richard Moore <rich@kde.org>
 *
 * This file is part of the KDE project
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#include "tcpslavebase.h"

#include <config.h>

#include <kdebug.h>
#include <kconfiggroup.h>
#include <kmessagebox.h>
#include <klocale.h>
#include <ktoolinvocation.h>
#include <network/ktcpsocket.h>

#include <QtCore/QDataStream>
#include <QtCore/QTime>
#include <QtNetwork/QTcpSocket>
#include <QtNetwork/QHostInfo>
#include <QtNetwork/QSslConfiguration>
#include <QtDBus/QtDBus>


using namespace KIO;
//using namespace KNetwork;

typedef QMap<QString, QString> StringStringMap;
Q_DECLARE_METATYPE(StringStringMap)

namespace KIO {
Q_DECLARE_OPERATORS_FOR_FLAGS(TCPSlaveBase::SslResult)
}

//TODO Proxy support whichever way works; KPAC reportedly does *not* work.
//NOTE kded_proxyscout may or may not be interesting

//TODO resurrect SSL session recycling; this means save the session on disconnect and look
//for a reusable session on connect. Consider how HTTP persistent connections interact with that.

//TODO in case we support SSL-lessness we need static KTcpSocket::sslAvailable() and check it
//in most places we ATM check for d->isSSL.

//TODO check if d->isBlocking is honored everywhere it makes sense

//TODO fold KSSLSetting and KSSLCertificateHome into KSslSettings and use that everywhere.

//TODO recognize partially encrypted websites as "somewhat safe"

/* List of dialogs/messageboxes we need to use (current code location in parentheses)
 - Can the "dontAskAgainName" thing be improved?

 - "SSLCertDialog" [select client cert] (SlaveInterface)
 - Enter password for client certificate (inline)
 - Password for client cert was wrong. Please reenter. (inline)
 - Setting client cert failed. [doesn't give reason] (inline)
 - "SSLInfoDialog" [mostly server cert info] (SlaveInterface)
 - You are about to enter secure mode. Security information/Display SSL information/Connect (inline)
 - You are about to leave secure mode. Security information/Continue loading/Abort (inline)
 - Hostname mismatch: Continue/Details/Cancel (inline)
 - IP address mismatch: Continue/Details/Cancel (inline)
 - Certificate failed authenticity check: Continue/Details/Cancel (inline)
 - Would you like to accept this certificate forever: Yes/No/Current sessions only (inline)
 */


/** @internal */
class TCPSlaveBase::TcpSlaveBasePrivate
{
public:
    TcpSlaveBasePrivate(TCPSlaveBase* qq) : q(qq) {}

    SslResult startTLSInternal(KTcpSocket::SslVersion sslVersion,
                               const QSslConfiguration& configuration = QSslConfiguration(),
                               int waitForEncryptedTimeout = -1);

    TCPSlaveBase* q;

    bool isBlocking;

    KTcpSocket socket;

    QString host;
    QString ip;
    quint16 port;
    QByteArray serviceName;
};


//### uh, is this a good idea??
QIODevice *TCPSlaveBase::socket() const
{
    return &d->socket;
}


TCPSlaveBase::TCPSlaveBase(const QByteArray &protocol,
                           const QByteArray &poolSocket,
                           const QByteArray &appSocket,
                           bool autoSSL)
 : SlaveBase(protocol, poolSocket, appSocket),
   d(new TcpSlaveBasePrivate(this))
{
    d->isBlocking = true;
    d->port = 0;
    d->serviceName = protocol;
    // Limit the read buffer size to 14 MB (14*1024*1024) (based on the upload limit
    // in TransferJob::slotDataReq). See the docs for QAbstractSocket::setReadBufferSize
    // and the BR# 187876 to understand why setting this limit is necessary.
    d->socket.setReadBufferSize(14680064);
}


TCPSlaveBase::~TCPSlaveBase()
{
    delete d;
}


ssize_t TCPSlaveBase::write(const char *data, ssize_t len)
{
    ssize_t written = d->socket.write(data, len);
    if (written == -1) {
        kDebug(7027) << "d->socket.write() returned -1! Socket error is"
                     << d->socket.error() << ", Socket state is" << d->socket.state();
    }

    bool success = false;
    if (d->isBlocking) {
        // Drain the tx buffer
        success = d->socket.waitForBytesWritten(-1);
    } else {
        // ### I don't know how to make sure that all data does get written at some point
        // without doing it now. There is no event loop to do it behind the scenes.
        // Polling in the dispatch() loop? Something timeout based?
        success = d->socket.waitForBytesWritten(0);
    }

    d->socket.flush();  //this is supposed to get the data on the wire faster

    if (d->socket.state() != KTcpSocket::ConnectedState || !success) {
        kDebug(7027) << "Write failed, will return -1! Socket error is"
                     << d->socket.error() << ", Socket state is" << d->socket.state()
                     << "Return value of waitForBytesWritten() is" << success;
        return -1;
    }

    return written;
}


ssize_t TCPSlaveBase::read(char* data, ssize_t len)
{
    if (!d->socket.bytesAvailable()) {
        const int timeout = d->isBlocking ? -1 : (readTimeout() * 1000);
        d->socket.waitForReadyRead(timeout);
    }
#if 0
    // Do not do this because its only benefit is to cause a nasty side effect
    // upstream in Qt. See BR# 260769.
    else if (d->socket.encryptionMode() != KTcpSocket::SslClientMode ||
               QNetworkProxy::applicationProxy().type() == QNetworkProxy::NoProxy) {
        // we only do this when it doesn't trigger Qt socket bugs. When it doesn't break anything
        // it seems to help performance.
        d->socket.waitForReadyRead(0);
    }
#endif
    return d->socket.read(data, len);
}


ssize_t TCPSlaveBase::readLine(char *data, ssize_t len)
{
    const int timeout = (d->isBlocking ? -1: (readTimeout() * 1000));
    ssize_t readTotal = 0;
    do {
        if (!d->socket.bytesAvailable())
            d->socket.waitForReadyRead(timeout);
        ssize_t readStep = d->socket.readLine(&data[readTotal], len-readTotal);
        if (readStep == -1 || (readStep == 0 && d->socket.state() != KTcpSocket::ConnectedState)) {
            return -1;
        }
        readTotal += readStep;
    } while (readTotal == 0 || data[readTotal-1] != '\n');

    return readTotal;
}


bool TCPSlaveBase::connectToHost(const QString &/*protocol*/,
                                 const QString &host,
                                 quint16 port)
{
    QString errorString;
    const int errCode = connectToHost(host, port, &errorString);
    if (errCode == 0)
        return true;

    error(errCode, errorString);
    return false;
}

int TCPSlaveBase::connectToHost(const QString& host, quint16 port, QString* errorString)
{
    if (errorString) {
        errorString->clear();  // clear prior error messages.
    }

    d->socket.setVerificationPeerName(host); // Used for ssl certificate verification (SNI)


    /*
      By default the SSL handshake attempt uses these settings in the order shown:

      1.) Protocol: KTcpSocket::SecureProtocols   SSL compression: ON  (DEFAULT)
      2.) Protocol: KTcpSocket::SecureProtocols   SSL compression: OFF
      3.) Protocol: KTcpSocket::TlsV1             SSL compression: ON
      4.) Protocol: KTcpSocket::TlsV1             SSL compression: OFF
      5.) Protocol: KTcpSocket::SslV3             SSL compression: ON
      6.) Protocol: KTcpSocket::SslV3             SSL compression: OFF

      If any combination other than the one marked DEFAULT is used to complete
      the SSL handshake, then that combination will be cached using KIO's internal
      meta-data mechanism in order to speed up future connections to the same host.
    */

    const int timeout = (connectTimeout() * 1000);
    while (true) {
        disconnectFromHost();  //Reset some state, even if we are already disconnected
        d->host = host;

        d->socket.connectToHost(host, port);
        const bool connectOk = d->socket.waitForConnected(timeout > -1 ? timeout : -1);

        kDebug(7027) << "Socket: state=" << d->socket.state()
                     << ", error=" << d->socket.error()
                     << ", connected?" << connectOk;

        if (d->socket.state() != KTcpSocket::ConnectedState) {
            if (errorString)
                *errorString = host + QLatin1String(": ") + d->socket.errorString();
            switch (d->socket.error()) {
            case KTcpSocket::UnsupportedSocketOperationError:
                return ERR_UNSUPPORTED_ACTION;
            case KTcpSocket::RemoteHostClosedError:
                return ERR_CONNECTION_BROKEN;
            case KTcpSocket::SocketTimeoutError:
                return ERR_SERVER_TIMEOUT;
            case KTcpSocket::HostNotFoundError:
                return ERR_UNKNOWN_HOST;
            default:
                return ERR_COULD_NOT_CONNECT;
            }
        }

        //### check for proxyAuthenticationRequiredError

        d->ip = d->socket.peerAddress().toString();
        d->port = d->socket.peerPort();

        return 0;
    }
    Q_ASSERT(false);
    // Code flow never gets here but let's make the compiler happy.
    // More: the stack allocation of QSslSettings seems to be confusing the compiler;
    //       in fact, any non-POD allocation does. 
    //       even a 'return 0;' directly after the allocation (so before the while(true))
    //       is ignored. definitely seems to be a compiler bug? - aseigo
    return 0;
}

void TCPSlaveBase::disconnectFromHost()
{
    kDebug(7027);
    d->host.clear();
    d->ip.clear();

    if (d->socket.state() == KTcpSocket::UnconnectedState) {
        // discard incoming data - the remote host might have disconnected us in the meantime
        // but the visible effect of disconnectFromHost() should stay the same.
        d->socket.close();
        return;
    }

    //### maybe save a session for reuse on SSL shutdown if and when QSslSocket
    //    does that. QCA::TLS can do it apparently but that is not enough if
    //    we want to present that as KDE API. Not a big loss in any case.
    d->socket.disconnectFromHost();
    if (d->socket.state() != KTcpSocket::UnconnectedState)
        d->socket.waitForDisconnected(-1); // wait for unsent data to be sent
    d->socket.close(); //whatever that means on a socket
}

bool TCPSlaveBase::isUsingSsl() const
{
    return false;
}

quint16 TCPSlaveBase::port() const
{
    return d->port;
}

bool TCPSlaveBase::atEnd() const
{
    return d->socket.atEnd();
}

// Find out if a hostname matches an SSL certificate's Common Name (including wildcards)
static bool isMatchingHostname(const QString &cnIn, const QString &hostnameIn)
{
    const QString cn = cnIn.toLower();
    const QString hostname = hostnameIn.toLower();

    const int wildcard = cn.indexOf(QLatin1Char('*'));

    // Check this is a wildcard cert, if not then just compare the strings
    if (wildcard < 0)
        return cn == hostname;

    const int firstCnDot = cn.indexOf(QLatin1Char('.'));
    const int secondCnDot = cn.indexOf(QLatin1Char('.'), firstCnDot+1);

    // Check at least 3 components
    if ((-1 == secondCnDot) || (secondCnDot+1 >= cn.length()))
        return false;

    // Check * is last character of 1st component (ie. there's a following .)
    if (wildcard+1 != firstCnDot)
        return false;

    // Check only one star
    if (cn.lastIndexOf(QLatin1Char('*')) != wildcard)
        return false;

    // Check characters preceding * (if any) match
    if (wildcard && (hostname.leftRef(wildcard) != cn.leftRef(wildcard)))
        return false;

    // Check characters following first . match
    if (hostname.midRef(hostname.indexOf(QLatin1Char('.'))) != cn.midRef(firstCnDot))
        return false;

    // Check if the hostname is an IP address, if so then wildcards are not allowed
    QHostAddress addr(hostname);
    if (!addr.isNull())
        return false;

    // Ok, I guess this was a wildcard CN and the hostname matches.
    return true;
}

TCPSlaveBase::SslResult TCPSlaveBase::TcpSlaveBasePrivate::startTLSInternal (KTcpSocket::SslVersion version,
                                                                             const QSslConfiguration& sslConfig,
                                                                             int waitForEncryptedTimeout)
{
    q->selectClientCertificate();

    //setMetaData("ssl_session_id", d->kssl->session()->toString());
    //### we don't support session reuse for now...

    // Set the SSL version to use...
    socket.setAdvertisedSslVersion(version);

    // Set SSL configuration information
    if (!sslConfig.isNull())
        socket.setSslConfiguration(sslConfig);

    /* Usually ignoreSslErrors() would be called in the slot invoked by the sslErrors()
       signal but that would mess up the flow of control. We will check for errors
       anyway to decide if we want to continue connecting. Otherwise ignoreSslErrors()
       before connecting would be very insecure. */
    socket.ignoreSslErrors();
    socket.startClientEncryption();
    const bool encryptionStarted = socket.waitForEncrypted(waitForEncryptedTimeout);

    //Set metadata, among other things for the "SSL Details" dialog
    KSslCipher cipher = socket.sessionCipher();

    if (!encryptionStarted || socket.encryptionMode() != KTcpSocket::SslClientMode
        || cipher.isNull() || cipher.usedBits() == 0 || socket.peerCertificateChain().isEmpty()) {
        kDebug(7029) << "Initial SSL handshake failed. encryptionStarted is"
                     << encryptionStarted << ", cipher.isNull() is" << cipher.isNull()
                     << ", cipher.usedBits() is" << cipher.usedBits()
                     << ", length of certificate chain is" << socket.peerCertificateChain().count()
                     << ", the socket says:" << socket.errorString()
                     << "and the list of SSL errors contains"
                     << socket.sslErrors().count() << "items.";
        Q_FOREACH(const KSslError& sslError, socket.sslErrors()) {
            kDebug(7029) << "SSL ERROR: (" << sslError.error() << ")" << sslError.errorString();
        }
        return ResultFailed | ResultFailedEarly;
    }

    kDebug(7029) << "Cipher info - "
                 << " advertised SSL protocol version" << socket.advertisedSslVersion()
                 << " negotiated SSL protocol version" << socket.negotiatedSslVersion()
                 << " authenticationMethod:" << cipher.authenticationMethod()
                 << " encryptionMethod:" << cipher.encryptionMethod()
                 << " keyExchangeMethod:" << cipher.keyExchangeMethod()
                 << " name:" << cipher.name()
                 << " supportedBits:" << cipher.supportedBits()
                 << " usedBits:" << cipher.usedBits();

    // Since we connect by IP (cf. KIO::HostInfo) the SSL code will not recognize
    // that the site certificate belongs to the domain. We therefore do the
    // domain<->certificate matching here.

    // Redo name checking here and (re-)insert HostNameMismatch to sslErrors if
    // host name does not match any of the names in server certificate.
    // QSslSocket may not report HostNameMismatch error, when server
    // certificate was issued for the IP we are connecting to.

    q->sendAndKeepMetaData();

    return SslResult();
}

bool TCPSlaveBase::isConnected() const
{
    //QSslSocket::isValid() and therefore KTcpSocket::isValid() are shady...
    return d->socket.state() == KTcpSocket::ConnectedState;
}


bool TCPSlaveBase::waitForResponse(int t)
{
    if (d->socket.bytesAvailable()) {
        return true;
    }
    return d->socket.waitForReadyRead(t * 1000);
}

void TCPSlaveBase::setBlocking(bool b)
{
    if (!b) {
        kWarning(7029) << "Caller requested non-blocking mode, but that doesn't work";
        return;
    }
    d->isBlocking = b;
}

void TCPSlaveBase::virtual_hook(int id, void* data)
{
    if (id == SlaveBase::AppConnectionMade) {
    } else {
        SlaveBase::virtual_hook(id, data);
    }
}
