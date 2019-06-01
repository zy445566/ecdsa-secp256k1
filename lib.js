// T = (p, a, b, G, n, h)
// E : y^2 ≡ x^3 + ax + b (mod p)
// 相同的点相加第一式: λ≡(3x1^2+ a)/2y1(mod p)
// 相同的点相加第二式: x3 ≡ λ^2 − 2x1 (mod p), y3≡ λ(x1 − x3) − y1 (mod p)
// 不同的点相加第一式: λ≡ （y2 − y1）/（x2 − x1）(mod p)
// 不同的点相加第二式: x3 ≡ λ^2 − x1 − x2 (mod p), y3 ≡ λ(x1 − x3) − y1 (mod p)


function num2Point(num){
    let numHex = num.toString(16);
    let len = 129;
    if(numHex.length!=len){
        throw new Error(`point num length must be ${len}!`);
    }
    if(numHex[0]!='4') {
        throw new Error('point num data not right!');
    }
    let startX = 1;
    let startY= 65;
    let offset = 64;
    return {x:BigInt(`0x${numHex.slice(startX,startX+offset)}`),y:BigInt(`0x${numHex.slice(startY,startY+offset)}`)};

}

function point2HexStr(point) {
    return `0x04${point.x.toString(16)}${point.y.toString(16)}`;
}

function point2Num(point) {
    return BigInt(point2HexStr(point));
}

function postiveMod(num,modNum) {
    return (num%modNum + modNum)%modNum;
}
// 欧几里德算法求乘法逆元
function inverseMulti(x,modNum) {
    let x1= 1n,x2 = 0n,x3 = modNum;
    let y1 = 0n,y2=1n,y3=(x%modNum+modNum)%modNum;
    let q;
    let t1,t2,t3;
    while(true){
        if(y3==0n)throw new Error('multiplicative inverse modulo is no answer!');
        if(y3==1n)return y2;
        q = x3/y3;
        t1=x1-q*y1;t2=x2-q*y2;t3=x3-q*y3;
        x1=y1;x2=y2;x3=y3;
        y1=t1;y2=t2;y3=t3;
    }
}

function getPrivteKeyNumByRand(n) {
    let nHex = n.toString(16);
    let privteKeyList = [];
    let isZero = true;
    for(let i=0;i<nHex.length;i++) {
        let rand16Num = Math.round(Math.random()*parseInt(nHex[i],16));
        privteKeyList.push(rand16Num.toString(16));
        if(rand16Num>0) {isZero = false;}
    }
    if(isZero){return getPrivteKeyNumByRand(n);}
    return BigInt(`0x${privteKeyList.join('')}`);
}

function addSamePoint(x1,y1,modNum,a) {
    let ru = postiveMod((3n*(x1**2n)+a)*inverseMulti(2n*y1, modNum), modNum);
    let x3 = postiveMod((ru**2n) - (2n*x1), modNum);
    let y3 = postiveMod(ru*(x1-x3) - y1, modNum);
    return {x:x3,y:y3};
}
function addDiffPoint(x1,y1,x2,y2,modNum) {
    let ru = postiveMod((y2-y1)*inverseMulti(x2-x1, modNum), modNum);
    let x3 = postiveMod(ru**2n - x1 - x2, modNum);
    let y3 = postiveMod(ru*(x1-x3)-y1, modNum);
    return {x:x3,y:y3};
}

function getPointByNum(num,pointG,p,a) {
    let numBin = num.toString(2);
    let nowPoint = null;
    let nextPoint = pointG;
    for(let i=numBin.length-1;i>=0;i--) {
        if(numBin[i]=='1') {
            if(nowPoint === null) {
                nowPoint = nextPoint;
            } else {
                nowPoint = addDiffPoint(nowPoint.x,nowPoint.y,nextPoint.x,nextPoint.y,p);
            }
        }
        nextPoint = addSamePoint(nextPoint.x,nextPoint.y,p,a);
    }
    return nowPoint;
}

/**
 * s = k^-1 (e + rd) mod n 
 * M为要签名消息,d为私钥的值
 */
function sign(n,pointG,p,a,d,mNum) {
    let k,R;
    let r = 0n;
    while(r==0n) {
        k = getPrivteKeyNumByRand(n);
        R = getPointByNum(k,pointG,p,a);
        r = postiveMod(R.x,n);
    }
    let e = mNum;
    let s = postiveMod(((e+(r*d))*inverseMulti(k,n)),n);
    if(s==0n) {
        return sign(n,pointG,p,a,d,M,encoding);
    }
    return {r,s};
}
/**
 * 
 * @param {*} pointQ 为我的公钥原值的点
 */
function verify(n,pointG,p,a,pointQ,S,mNum) {
    let {r,s} = S;
    if(!(r>0n && r<n && s>0n && s<n)){return false;}
    let e = mNum;
    let w = inverseMulti(s,n);
    let u1 = postiveMod((e*w),n);
    let u2 = postiveMod((r*w),n);
    let u1Point = getPointByNum(u1,pointG,p,a);
    let u2Point = getPointByNum(u2,pointQ,p,a);
    let pointR;
    if(u1Point.x==u2Point.x && u1Point.y==u2Point.y) {
        pointR = addSamePoint(u1Point.x,u1Point.y,p,a);
    } else {
        pointR = addDiffPoint(u1Point.x,u1Point.y,u2Point.x,u2Point.y,p);
    }
    if(pointR.x==0n && pointR.y==0n) {return false;}
    let v = postiveMod(pointR.x,n);
    if(v==r) {
        return true;
    }
    return false;
}

module.exports = {
    num2Point,
    point2HexStr,
    point2Num,
    getPrivteKeyNumByRand,
    addSamePoint,
    addDiffPoint,
    getPointByNum,
    sign,
    verify
}