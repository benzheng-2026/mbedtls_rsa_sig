
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
** Encryption schemes
*** RSARSAES-PKCS1-v1_5
*** RSAES-OAEP
** Signature schemes
*** RSASSA-PKCS1-v1_5
*** RSASSA-PSS
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

