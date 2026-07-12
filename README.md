
# 1.功能说明
我希望实现RSA 公钥加密，PKCS1.5填充
- 请给我一个实现流程
- 请给我一个实现代码示例

# 步骤
##  1. 生成私钥对
### 生成RSA 2048位私钥（已在README中存在）
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048

### 从私钥中提取公钥（新增步骤）
openssl rsa -pubout -in private_key.pem -out public_key.pem


# 2. 编译加密程序
编译使用CMake，不要使用手动gcc
# 3. 运行加密程序




```plantuml
@startmindmap
* PKCS#1
**  Key Types
*** RSA Public Key
*** RSA Private Key
**  Data Conversion Primitives （数据转换原语）
*** I2OSP
*** OS2IP
**  Cryptographic Primitives （密码原语）
*** Encryption and Decryption Primitives（加解密原语）
**** RSAEP
**** RSADP
*** Signature and Verification Primitives（签名验证原语）
**** RSASP1
**** RSAVP1
**  Encryption Schemes（加解密）
*** RSAES-OAEP
*** RSAES-PKCS1-v1_5
**  Signature Scheme with Appendix（签名方案）
*** RSASSA-PSS
*** RSASSA-PKCS1-v1_5
**  Encoding Methods for Signatures with Appendix（签名编码方法）
*** EMSA-PSS
**** Encoding Operation
**** Verification Operation
*** EMSA-PKCS1-v1_5


@endmindmap
```


```plantuml
@startuml
skinparam backgroundColor #FEFEFE
skinparam activity {
  BackgroundColor #E3F2FD
  BorderColor #1565C0
  ArrowColor #1565C0
  FontName Arial
  FontSize 14
}
skinparam partition {
  BackgroundColor #FAFAFA
  BorderColor #BDBDBD
}

title RSAES-PKCS1-v1_5 Encryption Scheme

start

:Message **M**;

:Generate Random Padding String **PS**
*(len(PS) = k - 3 - len(M), PS bytes ≠ 0x00)*;

partition "Encoding Operation (EME-PKCS1-v1_5)" {
  :Construct Encoded Message **EM**
  **EM** = `00` || `02` || **PS** || `00` || **M**;
}

partition "RSA Encryption Primitive (RSAEP)" {
  :Convert **EM** to Integer
  **m** = OS2IP(**EM**);
  
  :Apply RSA Public Key Operation
  **c** = **m**^e mod **n**;
}

partition "Conversion to Ciphertext" {
  :Convert Integer to Octet String
  **C** = I2OSP(**c**, k);
}

:Ciphertext **C**;

stop

@enduml
```



# 从私钥提取公钥
openssl rsa -in private_key.pem -pubout -out public_key.pem

