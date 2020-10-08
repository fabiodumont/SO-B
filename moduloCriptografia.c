#include <linux/init.h>     //Funçoes __init, __exit 
#include <linux/module.h>   //Necessario pra qualquer modulo de kernel
#include <linux/device.h>   // Suporte para modulos de dispositivos
#include <linux/kernel.h>   //macros do kernel
#include <linux/fs.h>       // Suporte ao sistema de arquivos linux
#include <linux/uaccess.h>  //Função copy_to_user
#include <linux/crypto.h>   //Funçoes de criptografia
#include <crypto/skcipher.h>   //Funçoes de criptografia
#include <linux/mutex.h>    // Necessario para utilizar o mutex
#include <linux/scatterlist.h>
#include <crypto/internal/hash.h>
#include <linux/vmalloc.h>

#define DEVICE_NAME "crypto"    // dev/crypto
#define CLASS_NAME "cryptomodule" 
#define BLOCK_SIZE_C 16

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Fabio Dumont, Marcos Lelis, Rafael Perroni");
MODULE_DESCRIPTION("Modulo de criptografia");

static int majorNumber; //Guarda o numero do dispositivo
static struct class* cryptoClass = NULL; //O ponteiro para a struct de classe 
static struct device* cryptoDev = NULL;//O ponteiro para a struct de dispositivo 

/* Struct que guarda o resultado da cripto ou descriptografia */ 
struct tcrypt_result {
    struct completion completion;
    int err;
};
/* Junção com todas as structs utilizadas pelas funçoes de cryptografia */
struct skcipher_def 
{
    struct scatterlist sg[3];
    struct crypto_skcipher *tfm;
    struct skcipher_request *req;
    struct tcrypt_result result;
    struct crypto_wait wait;
};

char *key,*iv,*tempIv,*tempKey;
char *ivFinal;
char *keyFinal;//Guarda o array de strings recebidos do usuario
static int tamIv=0;
static int tamKey=0; //Para se lembrar do tamanho das strings

static DEFINE_MUTEX(crypto_mutex);
static int tamSaida, inputLen; 
static char *decrypted, *encrypted, *ivLocal;
static char hash[42]={0};
static char hashAscii[41]={0};
int pos,i;
char op, buf;

module_param(iv,charp,0000);
MODULE_PARM_DESC(iv,"Vetor de inicialização");

module_param(key,charp,0000);
MODULE_PARM_DESC(key,"Chave de criptografia");

static int dev_open(struct inode *, struct file *);
static int dev_release(struct inode *, struct file *);
static ssize_t dev_read(struct file *,char *,size_t,loff_t * );
static ssize_t dev_write(struct file *, const char *,size_t,loff_t *);
static void init_cifra(char *msgInput, char *msgOutput, int opc);
static void ascii2hexa(unsigned char *in, char *out, int len);
static int unpadding(char *string, int len);
static void padding(char *string, int len);
static void init_hash(char *textIn, char *digest, int qtdChar);

int converteASCII(char *string, char *ascii)
{ 
    char temp[2];
    int i, cont = 0, tam = strlen(string);
    for(i = 0; i < tam; i+=2){         
        temp[0]  = string[i];
        temp[1]  = string[i+1];
        sscanf(temp, "%hhx", &ascii[cont]);
        cont++;    
   }
   return 1;
}
//Estrutura que define qual função chamar quando 
//o dispositivo é requisitado
static struct file_operations fops = 
{
    .open = dev_open,
    .release = dev_release,
    .read = dev_read,
    .write = dev_write, 
};

//função do nascimento do módulo
static int __init crypto_init(void)
{
    mutex_init(&crypto_mutex);
      
        if(iv!=NULL)
        {
            tamIv=strlen(iv);
        } 
        
        if(key!=NULL)
        {
            tamKey=strlen(key);
        }    
        
        tempIv=vmalloc(32);
        tempKey=vmalloc(32);
        keyFinal=vmalloc(16);
        ivFinal=vmalloc(16);
        memcpy(tempIv,iv,strlen(iv));
        memcpy(tempKey,key,strlen(key));

        if(tamIv < 32) 
        {    
            padding(tempIv,tamIv); // 
        }
    
        if(tamKey < 32)
        {
            padding(tempKey,tamKey);
        }

        tempIv[32]='\0';
        tempKey[32]='\0';
        printk(KERN_INFO "CRYPTO: KEY = %s\n",tempKey);
        printk(KERN_INFO "CRYPTO: iv = %s\n",tempIv);
        
        converteASCII(tempKey,keyFinal);
        converteASCII(tempIv,ivFinal);
        keyFinal[16]='\0';
        ivFinal[16]='\0';

    // Codigos de registro
    //Tento alocar um majorNumber para o dispositivo*/
    majorNumber = register_chrdev(0,DEVICE_NAME,&fops); //vai de 0 a 256
    if(majorNumber<0)  
    {
        printk(KERN_ALERT "CRYPTO: Falhou em registrar o dispositivo\n");
        return majorNumber;
    }
    printk(KERN_INFO "CRYPTO: Dispositivo criado com o majorNumber = %d\n",majorNumber);

    //Registra a classe do dispositivo
    cryptoClass = class_create(THIS_MODULE,CLASS_NAME);
    if(IS_ERR(cryptoClass))
    {
        unregister_chrdev(majorNumber,DEVICE_NAME);
        printk(KERN_ALERT "CRYPTO: Falhou em registrar a classe\n");
        return PTR_ERR(cryptoClass);
    }
    printk(KERN_INFO "CRYPTO: Classe registrada\n");

    //Registra o dispositivo
    cryptoDev=device_create(cryptoClass,NULL,MKDEV(majorNumber,0),NULL,DEVICE_NAME);
    if(IS_ERR(cryptoDev))
    {
        class_destroy(cryptoClass);
        unregister_chrdev(majorNumber,DEVICE_NAME);
        printk(KERN_ALERT "CRYPTO--> FALHA AO REGISTRAR DISPOSITIVO\n");
        return PTR_ERR(cryptoDev);
    }
    printk(KERN_INFO "CRYPTO--> Dispositivo registrado\n\n\n");

    return 0;
}

//função assassinadora do módulo :-)
static void __exit crypto_exit(void)
{
    mutex_destroy(&crypto_mutex);
    device_destroy(cryptoClass,MKDEV(majorNumber,0));
    class_unregister(cryptoClass);
    class_destroy(cryptoClass);
    unregister_chrdev(majorNumber,DEVICE_NAME);
    printk(KERN_INFO "CRYPTO: ADEUS MUNDO!!\n\n\n");
}

static int dev_open(struct inode *inodep,struct file *filep)
{
    if(!mutex_trylock(&crypto_mutex)){
        printk(KERN_ALERT "CRYPTO--> Requisiçao bloqueada!!\n");
        return -EBUSY;
    }
    return 0;
}

static int dev_release(struct inode *inodep,struct file *filep)
{
    mutex_unlock(&crypto_mutex);
    printk(KERN_INFO "CRYPTO: Modulo dispensado!\n\n\n");
    return 0;
}

static ssize_t dev_read(struct file *filep,char *buffer,size_t len,loff_t *offset)
{
    int erros=0;
    //TODO aqui verificar se e para enviar o decrypted ou o encrypted
    
    if(op == 'c')
    {
        erros=copy_to_user(buffer,encrypted,tamSaida);
        vfree(encrypted);
    }
    else if(op == 'd')
    {
        vfree(decrypted);
        erros=copy_to_user(buffer,decrypted,tamSaida);
    }
    else
    {
        erros=copy_to_user(buffer,hash,tamSaida);
    }

    if(erros==0)
    {
        printk(KERN_INFO "CRYPTO: Mensagem com %d caracteres enviada!\\n",tamSaida);
        return 0;
    }
    else
    {
        printk(KERN_ALERT "CRYPTO: Falhou em enviar a mensagem\n");
        return -EFAULT;
    }
}

static ssize_t dev_write(struct file *filep,const char *buffer,size_t len, loff_t *offset)
{
    char temp[2];
    char *ascii;
    char *input;    
    char blocoIn[16]={0};
    char blocoCrypto[16]={0};
    int cont = 0, indice;

    op = buffer[0];
    inputLen = len - 1;
    if(inputLen%32 && op == 'd')
    {
        return -1;  // Retorna erro pois a entrada necessariamente precisa ter um tamanho de 32
    } 
        
    if(!(inputLen % 16))
    {
        input = vmalloc(inputLen + 32);
    }
    else
    {
        input = vmalloc(inputLen);    
    }

    if(!input)
    {
        printk(KERN_ERR "kmalloc(input) failed\n");
        return -ENOMEM;
    }

    if(!(inputLen % 16))
        ascii = vmalloc(inputLen/2 + 16);
    else
        ascii = vmalloc(inputLen/2);
    if (!ascii) 
    {
        printk(KERN_ERR  "kmalloc(ascii) failed\n");
        return -ENOMEM;
    }

    ivLocal = vmalloc(16);
    if (!ivLocal) 
    {
        printk(KERN_ERR  "kmalloc(input) failed\n");
        return -ENOMEM;
    }    

    memcpy(ivLocal, ivFinal, 16);
    memcpy(input, buffer+1,inputLen);
  

    if(op == 'c') {
        padding(input, inputLen); //Caso a opcao seja de criptgrafia, o padding eh feito na entrada.
        inputLen += 32 - (inputLen%32); //Atualiza o tamanho do texto apos o padding    
    } 
   
    //Conversao de hexa para ascii
    for(indice = 0; indice < inputLen; indice+=2){
        temp[0]  = input[indice];
        temp[1]  = input[indice+1];
        sscanf(temp, "%hhx", &ascii[cont]);
        cont++;    
    }

    if(op == 'c')
    {
        printk("CRYPTO: Criptografando..\n"); 
        // CRIPTOGRAFIA

        for(indice = 0; indice < cont/16; indice++)
        {//Cont tem a qtd de caracteres ascii, sempre multiplo de 16 (padding)            
            for(i = 0; i < 16; i++) //Copia um bloco para criptografar
            {
                blocoIn[i] = ascii[indice*16 + i];//Indice*16 para deslocar o bloco (Indice tem o num. do bloco)
            }

            init_cifra(blocoIn, blocoCrypto, 1); // Chama a funcao para fazer a cripto ou a descripto, dependendo do terceiro parametro
            
            for(i = 0; i < 16; i++) //Copia um bloco criptografado 
            {
                ascii[indice*16 +i] = blocoCrypto[i];//Como o bloco atual de ascii ja foi criptografado, ele eh sobrescrito
            }
        }

        encrypted=vmalloc(cont*2+1);

        if(!encrypted)
        {
            printk(KERN_ERR "kmalloc(encrypted) error");
        }

        ascii2hexa(ascii, encrypted, cont);//ascii tem todos os blocos criptografados
        tamSaida = cont*2;
        encrypted[cont*2] = '\0';

    }
    else if(op == 'd')
    {
        if(inputLen%32) return -1;//Caso a entrada nao seja multiplo de 32, retorna erro
        printk("CRYPTO: Descriptografando..\n"); 
        //descriptografia aqui

        for(indice = 0; indice < cont/16; indice++)
        {//Cont tem a qtd de caracteres ascii, sempre multiplo de 16 (padding)            
            for(i = 0; i < 16; i++)
            {//Copia um bloco para criptografar
                blocoIn[i] = ascii[indice*16 + i];//Indice*16 para deslocar o bloco (Indice tem o num. do bloco)
            }

            init_cifra(blocoIn, blocoCrypto, 2); // Chama a funcao para fazer a cripto ou a descripto, dependendo do terceiro parametro
            
            for(i = 0; i < 16; i++)
            {//Copia um bloco criptografado 
                ascii[indice*16 +i] = blocoCrypto[i];//Como o bloco atual de ascii ja foi criptografado, ele eh sobrescrito
            }
        }

        decrypted=vmalloc(cont*2);
        if(!decrypted){
            printk(KERN_ERR "kmalloc(encrypted) error");
        }

        ascii2hexa(ascii, decrypted, cont);
        tamSaida=cont*2;

        if(unpadding(decrypted, tamSaida) == 0)//Na descriptografia o unpadding eh feito na saida         
            return -1;                         //Retorna erro se nao tiver padding valido 

       // printk("DEBUG HEX2ASC %s\n", decrypted);
    }
    else if(op == 'h')
    {
        printk("CRYPTO: FAZENDO O HASH..\n");
        
        init_hash(ascii, hashAscii, cont);
        
        ascii2hexa(hashAscii, hash, 40);
        tamSaida = 40;
        hash[40]='\0';
    }
    else
    {
        printk("ERRO: OPCAO SELECIONADA NAO EXISTE\n");
        return -1;
    }

    vfree(ascii);
    vfree(input);
    vfree(ivLocal);
    return len;
}

static void ascii2hexa(unsigned char *in, char *out, int len)
{
    int i = 0;
    while (i < len){        
        sprintf(out+i*2, "%02x", *in++);
        i++;       
    }
}

static void init_cifra(char *msgInput, char *msgOutput, int opc)
{
        /* local variables */
        struct skcipher_request *req ;
        struct crypto_skcipher *skcipher = NULL;
        struct skcipher_def sk;
        int ret, i;
        char saida[16];
        char entrada[16];

        skcipher = crypto_alloc_skcipher("cbc(aes)", 0, 0);

        req = skcipher_request_alloc(skcipher, GFP_KERNEL);
        if (req == NULL) {
                printk("failed to load transform for aes");
                goto out;
        }

        ret = crypto_skcipher_setkey(skcipher, keyFinal, strlen(keyFinal));
        if (ret) {
                printk(KERN_ERR  "setkey() failed\n");
                goto out;
        }

        skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
            crypto_req_done,
            &sk.wait);        

        for(i = 0; i < 16; i++){
            entrada[i] = msgInput[i];
        } 

        sk.tfm = skcipher;
        sk.req = req;

        sg_init_one(&sk.sg[0], entrada, 16);
        sg_init_one(&sk.sg[1], saida, 16);

        if(opc == 1)
        {  
            skcipher_request_set_crypt(req, &sk.sg[0], &sk.sg[1], 16, ivLocal);
            crypto_init_wait(&sk.wait);
            init_completion(&sk.result.completion);
        
            ret = crypto_wait_req(crypto_skcipher_encrypt(sk.req), &sk.wait);
            if (ret) {
                printk(KERN_ERR  "encryption failed erro");
                goto out;
            }
        }
        else
        {
            skcipher_request_set_crypt(req, &sk.sg[0], &sk.sg[1], 16, ivLocal);
            crypto_init_wait(&sk.wait);
            init_completion(&sk.result.completion);
        
            ret = crypto_wait_req(crypto_skcipher_decrypt(sk.req), &sk.wait);
            if (ret) {
                printk(KERN_ERR  "encryption failed erro");
                goto out;
            }
        }

    for(i = 0; i < 16; i++)
    {
        msgOutput[i] = saida[i];
    }

    
out:
    if (skcipher)
        crypto_free_skcipher(skcipher);
    if (req)
        skcipher_request_free(req);       
}


static void padding(char *string, int len) // Faz o padding para preencher o bloco se necessario
{ 
    int qdtBlocos32, bytesOcupados;
    int i;
    qdtBlocos32 = len/32;   // Blocos que ja estao completos
    bytesOcupados = len%32; // Bytes usados no ultimo bloco (bloco que nao esta completo)

    if(bytesOcupados == 0) //Caso a string tenha o tamanho multiplo de 16, preenche um novo blco com o num 0x10 (tamanho do bloco)
    { 
        for(i = 0; i < 32; i++)
        {            
            sprintf(string + qdtBlocos32*32 + i*2,"%02x", 16);//Converte 16 decimal para hexa (0x10)
        }
    }

    else 
    {
        for(i = 0; i < (32 - bytesOcupados); i++) //O ultimo bloco eh preenchido com o valor da qtd de bytes livres
        {
            sprintf(string + qdtBlocos32*32 + i*2 + bytesOcupados,"%02x", (32 - bytesOcupados)/2);
         }
    }    
}

static int unpadding(char *string, int len)
{ 
    char temp[3];
    int qtdPadding; //Quantidade de bytes usados no padding
    int numP; //Numero usado para preencher o padding
    int i;

    temp[0]  = string[len-2]; //Ultimo numero sempre eh usado para calcular o padding
    temp[1]  = string[len-1];
    temp[2]  = '\0';    
    sscanf(temp, "%x", &qtdPadding); // Converte o num de hexa para decimal

    for(i = 0; i < qtdPadding*2; i += 2)
    {
        temp[0]  = string[len - 2 - i];
        temp[1]  = string[len - 1 - i];
        temp[2]  = '\0';
        sscanf(temp, "%x", &numP);
        if(numP != qtdPadding){//Caso o numero usado para preencher seja diferente da qtd, retorna erro
            printk("Erro de padding\n");
            return 0; 
        } 
    }
    string[len - qtdPadding*2] = '\0';//Descarta numeros usados no padding
    return 1;
}


static void init_hash(char *textIn, char *digest, int qtdChar)
{
    struct crypto_shash *sha1;
    struct shash_desc *shash;
    int ret;

    //Aloca identificador do resumo da mensagem com a criptografia(sha1) e as flags de tipo e parametros zeradas.
    sha1 = crypto_alloc_shash("sha1", 0, 0);
    //Verificando erro em crypto_alloc_shash... Em caso de erro, a flag IS_ERR sera true, e PTR_ERROR contera a mensagem de erro.
    if (IS_ERR(sha1)){
        printk(KERN_ERR  "hash failed erro: nao foi possivel alocar shash");
        return;
    }

    //Alocando Memoria para o identificador de estado operacional(sash) com 41 bytes, que ira conter o identificador 
    //do resumo da mensagem(variavel sha1), mensagem a ser criptada e seu respectivo resumo criptografico .
    shash = vmalloc(41);
    //Verificando erro... Se vmalloc retornar um numero menor 0, entao erro.
    if (!shash){
        printk(KERN_ERR  "hash failed erro: %i\n", ENOMEM);
        return;
    }


    //Inserindo o identificador do resumo da mensagem(variavel sha1) no identificador de estado operacional(shash).
    shash->tfm = sha1;
    //Atribuindo as flags para 0.
    shash->flags = 0;

    //(Re)iniciando a parte do retorno de resposta da criptografia no identificador de estado operacional(shash).
    ret = crypto_shash_init(shash);
    //Verificando erro... Se crypto_shash_init retornar um numero menor 0, entao erro.
    if (ret){
        printk(KERN_ERR  "hash failed erro: %i\n", ret);
        return;
    }        

    //Inserindo a mensagem a ser criptada no identificador de estado operacional(shash). 
    ret = crypto_shash_update(shash, textIn, qtdChar);
    //Verificando erro... Se crypto_shash_update retornar um numero menor 0, entao erro.
    if (ret){
        printk(KERN_ERR  "hash failed erro: %i\n", ret);
        return;
    }        
    
    //Calculando o resumo criptografico, que estara em digest...
    ret = crypto_shash_final(shash, digest);
    //Verificando erro... Se crypto_shash_final retornar um numero menor 0, entao erro.
    if (ret){
        printk(KERN_ERR  "hash failed erro: %i\n", ret);
        return;
    }        

    //Liberando memoria alocada para o shash...
    vfree(shash);
    //Liberando memoria alocada para o sha1...
    crypto_free_shash(sha1);
}


module_init(crypto_init);
module_exit(crypto_exit);

