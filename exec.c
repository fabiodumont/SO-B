#include<stdlib.h>
#include<errno.h>
#include<fcntl.h>
#include<string.h>
#include<unistd.h>

#define BUFFER_LENGTH 256               ///< tamanho do buffer
static char receive[BUFFER_LENGTH];     ///< o buffer que recebe

int main(){
   int ret, fd;
   char stringToSend[BUFFER_LENGTH];
   printf("INICIANDO\n");
   fd = open("/dev/ebbchar", O_RDWR);             // Abre com permissao de leitura e escrita
   if (fd < 0){
      perror("Falhou em abrir o dispositivo");
      return errno;
   }
   printf("Digite uma stirng para enviar para o modulo de kernel:\n");
   scanf("%[^\n]%*c", stringToSend);                // Le uma string (com espacos)
   printf("Escrevendo a mensagem [%s].\n", stringToSend);
   ret = write(fd, stringToSend, strlen(stringToSend)); // Envia a string
   if (ret < 0){
      perror("Falhou em escrever a mensagem no dispositivo ....");
      return errno;
   }

   printf("Pressione enter para ler do dispositivo ....\n");
   getchar();

   printf("Lendo do dispositivo ....\n");
   ret = read(fd, receive, BUFFER_LENGTH);        // Le a resposta
   if (ret < 0){
      perror("Falhou em ler a mensagem do dispositivo ....");
      return errno;
   }
   printf("A mensagem recebida eh: [%s]\n", receive);
   printf("Fim do programa\n");
   return 0;
}
