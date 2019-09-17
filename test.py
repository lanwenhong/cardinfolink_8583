#coding: utf-8
import rsa

#方法二
def rsa_ne_key(rsaExponent, rsaModulus):
    '''
    通过rsa包依据模数和指数生成公钥，实现加密
    :param rsaExponent:
    :param rsaModulus:
    :return:
    '''
    rsaExponent = int(rsaExponent, 16)  # 十六进制转十进制
    rsaModulus = int(rsaModulus, 16)
    key = rsa.PublicKey(rsaModulus, rsaExponent)
    return key

if __name__ == '__main__':
    rsaExponent = "010001"
    rsaModulus = "008baf14121377fc76eaf7794b8a8af17085628c3590df47e6534574efcfd81ef8635fcdc67d141c15f51649a89533df0db839331e30b8f8e4440ebf7ccbcc494f4ba18e9f492534b8aafc1b1057429ac851d3d9eb66e86fce1b04527c7b95a2431b07ea277cde2365876e2733325df04389a9d891c5d36b7bc752140db74cb69f"
    key = rsa_ne_key(rsaModulus, rsaExponent)

    print key
