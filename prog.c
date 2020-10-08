#include<stdio.h>
#include<stdlib.h>
#include<errno.h>
#include<fcntl.h>
#include<string.h>
#include<unistd.h>
#include<ctype.h>

int verifica_hexa(char entrada[]);
void converteParaHEXA(char *string, char *hexa);
void insereOPCeCopia(char *entrada, char *saida, char opc);
int converteParaASCII(char *string, char ascii[]);

int main(int argc, char *argv[]){

   uid_t uid=getuid();
   int option=-99;
   int ret,crypto;
   char *operacao = argv[1];
   char *msgHexa;
   char *temp, *temp2;
   static char *recebido;
   static char recebidoHash[41];
   int flagHexa=0;
   
   if(strcmp(operacao,"c")==0) 
   {
      option=1;
   }

   if(strcmp(operacao,"d")==0) 
   {
      option=2;
   }
   
   if(strcmp(operacao,"h")==0) 
   {
       option=3;
   }

   crypto = open("/dev/crypto",O_RDWR);
   if(crypto < 0)
   {
     perror("Falha ao acessar dispositivo...");
     return errno;            
   }

   if(argv[3] !=NULL)
   {     // verifica se mandou como hexa

      if(strcmp(argv[3],"--hexa")==0)
      {
        if(verifica_hexa(argv[2]) == 1)
        {
           flagHexa=1;
           msgHexa=malloc(strlen(argv[2])+1);
           temp=malloc(strlen(argv[2]));
        }
        else
        {
            printf("A entrada nao esta em formato hexa!\n");
        }
      }
   }
   else
   {
      msgHexa=malloc(strlen(argv[2])*2+1);
      temp=malloc(strlen(argv[2])*2);
   }
      
   recebido=malloc(strlen(argv[2])*2+32);
  

   switch (option)
   {
      case 1:
         printf("c - CRIPTOGRAFAR\n");

         if(flagHexa==0)
         {
            converteParaHEXA(argv[2], temp);
         }
         else
         {
            strcpy(temp,argv[2]);
            temp2=malloc(strlen(argv[2]));
            converteParaASCII(temp, temp2);
            printf("String a ser criptografada (em ASCII): %s\n", temp2);
         }

         insereOPCeCopia(temp,msgHexa,'c');

         printf("\nString a ser criptografada (em hexa): %s\n", msgHexa+1);
         
         ret = write(crypto,msgHexa,strlen(msgHexa));
         if(ret < 0){
            perror("Falha ao enviar dado ao dispositivo...");
            return errno;
         }

         printf("CRIPTOGRAFANDO...\n");
         
         ret = read(crypto,recebido,strlen(recebido));
         if(ret < 0){
            perror("Falha ao ler dado do dispositivo...");
            return errno;
         }
         printf("\nString criptografada: %s\n",recebido);   
      break;

      case 2:
         printf("d - DESCRIPTOGRAFAR\n");
          
         insereOPCeCopia(argv[2], msgHexa, 'd');

         printf("\nString a ser descriptografada: %s\n",msgHexa+1);
         
         ret = write(crypto,msgHexa,strlen(msgHexa));
         if(ret < 0){
	      if (ret == -1){
            	perror("Nao e possivel descriptografar esta mensagem, tente novamente");
            	return errno;
         	}
            perror("Falha ao enviar dado ao dispositivo...");
            return errno;
         }

         printf("DESCRIPTOGRAFANDO...\n");

         ret = read(crypto,recebido,strlen(recebido));
         if(ret < 0){
            perror("Falha ao ler dado do dispositivo...");
            return errno;
         }

 	      temp = malloc((strlen(recebido))/2); // aloca espaco para o dado em ascii para fazer o teste
	 
         
         printf("\nString ja descriptografada (em hexa): %s",recebido);
         if(converteParaASCII(recebido, temp))  // converte para ascii para o usuario visualizar melhor
	         printf("\nString ja descriptografada (em ASCII): %s\n",temp);
         else
            printf("\nNao foi possivel converter a string para ASCII\n");
      
      break;

      case 3:
         printf("h - FAZER O HASH\n");

         if(flagHexa==0){
            //printf("String para fazer o HASH (em ASCII): %s\n", argv[2]);
            converteParaHEXA(argv[2], temp);
         }
         else{
            strcpy(temp,argv[2]);
            temp2=malloc(strlen(argv[2]));
            converteParaASCII(temp, temp2);
            printf("String para fazer o HASH (em ASCII): %s\n", temp2);

         }

         insereOPCeCopia(temp,msgHexa,'h');

         printf("\nString para fazer o HASH (em hexa): %s\n", msgHexa+1);
         

         ret = write(crypto,msgHexa,strlen(msgHexa));
         if(ret < 0){
            perror("Falha ao enviar dado ao dispositivo...");
            return errno;
         }

         printf("FAZENDO O HASH (SHA1)...\n");

         ret = read(crypto,recebidoHash,40);
         if(ret < 0){
            perror("Falha ao ler dado do dispositivo...");
            return errno;
         }

         printf("\nHash: %s\n",recebidoHash); 

      break;

      default:

      printf("VAAAAI FILHAO");

   }   
   return 0;
}

int verifica_hexa(char entrada[])
{
   for(int i = 0; i < strlen(entrada); i++)
   {
      if(!((                                          // !!!!! IF NEGADO !!!!!
         (entrada[i] >= 48 && entrada[i] <= 57) ||    //Se letra esta entre 0(48 em ASCII) e 9(57 em ASCII)
         (entrada[i] >= 65 && entrada[i] <= 70) ||    // ou letra esta entre A(65 em ASCII) e F(70 em ASCII)
         (entrada[i] >= 97 && entrada[i] <= 102)) &&  // ou letra esta entre a(97 em ASCII) e a(102 em ASCII) 
         ((strlen(entrada) % 2) == 0)))               // E a cadeia de caracteres eh par
      {
         return 0;
      }
   }

   return 1;
}


void converteParaHEXA(char *string, char hexa[]){
   int tam = strlen(string);
   int i;
   for(i = 0; i < tam; i++){        
      sprintf(hexa+i*2,"%02x", string[i]);
   }
   sprintf(hexa+i*2+1,"%c",'\0'); 
}

void insereOPCeCopia(char entrada[], char saida[], char opc){
   int tam, i;
   tam = strlen(entrada);

   saida[0]= opc;
   for(i = 0; i < tam; i++){
      saida[i+1] = entrada[i];
   }
   saida[i+1]='\0';   
}

int converteParaASCII(char *string, char ascii[]){ 
    char temp[2];
    int i;    
    int cont = 0;
    int tam = strlen(string);
    for(i = 0; i < tam; i+=2){         
        temp[0]  = string[i];
        temp[1]  = string[i+1];
        sscanf(temp, "%hhx", &ascii[cont]);
        if (!isprint(ascii[cont]))
            return 0;
        cont++;    
   }
   return 1;
}



