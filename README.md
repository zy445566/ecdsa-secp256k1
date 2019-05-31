# ecdsa-secp256k1
[![Build Status](https://travis-ci.org/zy445566/ecdsa-secp256k1.svg?branch=master)](https://travis-ci.org/zy445566/ecdsa-secp256k1) 
[![codecov](https://codecov.io/gh/zy445566/ecdsa-secp256k1/branch/master/graph/badge.svg)](https://codecov.io/gh/zy445566/ecdsa-secp256k1)

only one no dependencied ecdsa secp256k1 by native js.

attention：`node version request >= 12.0`

# use
## get private key by rand
```js
let ecdsa = require('ecdsa-secp256k1');
ecdsa.randPrivateKeyNum().toString(16);//maybe output:b1904389afc66e8c5ec5165c4eb82d44237cc1409430302b31414a6b90123120
``` 
## get public key by private key Num
```js
let privateKeyNum = 0xeddbdc1168f1daeadbd3e44c1e3f8f5a284c2029f78ad26af98583a499de5b19n;
let publicKeyPoint = ecdsa.getPublicKeyPoint(privateKeyNum);
ecdsa.publicKeyPoint2HexStr(publicKeyPoint);//output: 4ea279824636aa9172473b6c3076727f17dada14847305487405a38a09c91ce6d63478f426ddcf618be66568cb6bd5bd7201c71689705d9602ae0a7c131a3bafb
```
## sign && verify
```js
let privateKeyNum = 0xeddbdc1168f1daeadbd3e44c1e3f8f5a284c2029f78ad26af98583a499de5b19n;
let publicKeyPoint = {
    x: 0xea279824636aa9172473b6c3076727f17dada14847305487405a38a09c91ce6dn,
    y: 0x63478f426ddcf618be66568cb6bd5bd7201c71689705d9602ae0a7c131a3bafbn
}
let msgData = 'Test Data';
let sha1 = crypto.createHash('sha256').update(msgData).digest('hex');
let msgDataNum = BigInt(`0x${sha1}`);
let signData = ecdsa.sign(privateKeyNum,msgDataNum);
ecdsa.verify(publicKeyPoint,signData,msgDataNum);//output:true
```