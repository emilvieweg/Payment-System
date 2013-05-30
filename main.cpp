#include <QCoreApplication>
#include <QtCrypto/qca.h>
#include <QDebug>
#include <QCryptographicHash>
#include <QHash>
#include <QFile>
#include <QTcpSocket>
#include <QHostAddress>
using namespace QCA;
QByteArray sendToServer(QByteArray message);
QByteArray toHash(PublicKey key);
bool transferMoney(PrivateKey sender,QByteArray reciver,double);

QByteArray SendToServer(QByteArray message)
{
    QTcpSocket socket;
    socket.connectToHost(QHostAddress("127.0.0.1"),15000);
    socket.waitForConnected();
    socket.write(message);
    socket.waitForReadyRead();
    socket.disconnectFromHost();
    return socket.readAll();
}


QByteArray serverBer= QByteArray::fromBase64("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0cP7MF0OEF1Sw8edGiiTFMd54FziVRfJMyCBx8lheyXcUb9j28StKl5psQUC8g8jQzWIIufEv3ySGdCsEJqx2+OBy5NjpLYFX9yRVSgox3dazb+khp5bBbs4GaPmmC7pC9P39wZ+8wVR966XfrioHu8/e+7iJJ9NHV73Aiw9/OujvYYXtngDMxzEeAc221shtSDHMdYiAKTgrma85vS2woKuQFpX0hvQa9Iil3k3qiAq0dY85rxzai8A2Ity5sbkyRJ4G7yDjOZwgoF5uNBHYoxs23OCrNVHjDRDELGqIJaTwEjuYTwkaCCyjsUg5e6jrRrU5Ujzj/zmFeYqvlFnJQIDAQAB");

QByteArray toHash(PublicKey key){
    return Hash("sha1").hash(key.toDER()).toByteArray().toBase64();
}

bool transferMoney(PrivateKey sender,QByteArray reciver,double amount){

    QByteArray msg= "Transfer\n"+toHash(sender.toPublicKey()) +" "+QVariant(amount).toByteArray()+" "+reciver+"\n\n";
    msg=msg+sender.signMessage(msg,EMSA1_SHA1);
    qDebug() << SendToServer(msg);
    return true;
    //return SendToServer(msg)=="OK" ?  1:0;
}



bool sendPubKey(PublicKey key)
{
    if(SendToServer(QByteArray("Add Key\n"+key.toDER()))=="OK")
        return 1;
    else
        return 0;
}

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);
    Initializer init;
    ConvertResult result;

    PublicKey serverPubKey= PublicKey::fromDER(serverBer);


    if(!QFile::exists("secretkey.pem"))
    {
       KeyGenerator().createRSA(1024).toPEMFile("secretkey.pem");
    }
    PrivateKey privkey = PrivateKey::fromPEMFile("secretkey.pem",SecureArray(),&result);
    if(!result==ConvertGood)
        qDebug() << "error cant read private key";


    //transferMoney(privkey,toHash(serverPubKey),0.1);
    sendPubKey(privkey.toPublicKey());

    return a.exec();
}
