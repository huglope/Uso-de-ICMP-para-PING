// Practica Tema 8: Lopez Alvarez, Hugo
#include "ip-icmp-ping.h"
#include<unistd.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<errno.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<string.h>
#include<netdb.h>

#include<sys/time.h>
#include<sys/types.h>

// Variables Globales
EchoRequest datagrama;

// Declaraciones de funciones
unsigned int calculoChecksum ();
char* errores(unsigned char type, unsigned char code);
int main (int argc, char* argv[]){
	// Se declaran las variables
	int sock, retval, verbose = 0;
	socklen_t tam = sizeof(struct sockaddr_in);
	EchoReply respuesta;
	struct sockaddr_in dirsock, cliente;
	unsigned char tipo, codigo;
	fd_set timeout;
	struct timeval tiempo;

	// Se comprueba que el numero de argumentos es correcto
	if(argc != 2 && argc != 3){
		fprintf(stderr, "La estructura del comando debe ser: ./miping [direccion IP] [-v]\n");
		exit(-1);
	}

	// Se comprueba si se ha optado por elegir la opcion verbose
	if(argc == 3 && strcmp(argv[2], "-v") == 0) verbose = 1;
	else if (argc == 3){
		fprintf(stderr, "La opcion %s no está disponible, solo se permite \"-v\"\n", argv[3]);
		exit(-1);
	}

	// Se abre el socket
	if((sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0){
		perror("socket()");
		exit(EXIT_FAILURE);
	}

	// Se transforma y asigna el argumento introducido en el campo IP del destinatario
	if(inet_aton(argv[1], &dirsock.sin_addr) == 0){
		fprintf(stderr, "El campo de la IP es erroneo\n");
		exit(-1);
	}

	// Se rellenan los campos del destinatario
	dirsock.sin_family = AF_INET;
	dirsock.sin_port = 0;

	// Se rellenan los campos del origen
	cliente.sin_family = AF_INET;
	cliente.sin_addr.s_addr = INADDR_ANY;
	cliente.sin_port = 0;

	// Se vincula el socket para la conexion
	if(bind(sock, (struct sockaddr *) &cliente, sizeof(struct sockaddr_in)) < 0){
		perror("bind()");
		exit(EXIT_FAILURE);
	}

	// Se imprimen los mensajes del verbose
	if(verbose) printf("-> Generando cabecera ICMP\n");

	// Se rellenan los campos del datagrama que se va a enviar
	datagrama.icmpHdr.type = 8;
	datagrama.icmpHdr.code = 0;
	datagrama.icmpHdr.checksum = 0;

	datagrama.pid = (unsigned short int) getpid();
	datagrama.sequence = 0;
	strcpy(datagrama.payload, "Sergio me esta copiando");

	datagrama.icmpHdr.checksum = (unsigned short int)calculoChecksum();
	// Comprobacion del checksum
//	printf("comprueba checksum %d\n", (unsigned short int) calculoChecksum());

	// Se imprimen los mensajes del verbose
	if(verbose){
		printf("-> Type: %u\n", datagrama.icmpHdr.type);
		printf("-> Code: %u\n", datagrama.icmpHdr.code);
		printf("-> PID : %u\n", datagrama.pid);
		printf("-> Sequence Number: %u\n", datagrama.sequence);
		printf("-> Cadena a enviar: %s\n", datagrama.payload);
		printf("-> Checksum: %u\n", datagrama.icmpHdr.checksum);
		printf("-> Tamano total del datagrama: %lu\n", sizeof(datagrama));
	}

	// Se envia el datagrama al destinatario
	if(sendto(sock, (unsigned char*) &datagrama, sizeof(datagrama), 0, (struct sockaddr *) &dirsock, sizeof(struct sockaddr_in)) < 0){
		perror("sendto()");
		exit(EXIT_FAILURE);
	}
	
	// Se imprimen mensajes de control
	printf("Mensaje ICMP enviado al host: %s\n", inet_ntoa(dirsock.sin_addr));

	// Se configuran los campos correspondientes para controlar que el socket se use en un maximo de 10 segundos
	FD_ZERO(&timeout);
	FD_SET(sock, &timeout);

	tiempo.tv_sec = 10; // Segundos
	tiempo.tv_usec = 0; // Microsegundos

	// Se comprubea el error de select
	if((retval = select(sock + 1, &timeout, NULL, NULL, &tiempo)) == -1){
		perror("select()");
		exit(EXIT_FAILURE);
	}
	// En caso de que si use el socket y por lo tanto se obtenga respuesta
	else if (retval){
	
		// Se recibe la respuesta del destinatario
		if(recvfrom(sock, (char *) &respuesta, sizeof(respuesta), 0, (struct sockaddr * ) &dirsock, &tam) < 0){
			perror("recvfrom()");
			exit(EXIT_FAILURE);
		}

		// Se imprime mensajes de control y de verbose
		printf("Respuesta recibida desde : %s\n", inet_ntoa(respuesta.ipHdr.iaSrc));
		if(verbose){
			printf("-> Tamano de la respuesta: %lu\n", sizeof(respuesta));
			printf("-> Cadena recibida: %s\n", respuesta.icmpMsg.payload);
			printf("-> PID: %u\n", respuesta.icmpMsg.pid);
			printf("-> TTL: %u\n", respuesta.ipHdr.TTL);
		}
	
		// Se asignan los valores correspondientes a las variables
		tipo = respuesta.icmpMsg.icmpHdr.type;
		codigo = respuesta.icmpMsg.icmpHdr.code;
	
		// Se imprime el tipo de error
		if (tipo  == 0) printf("Respuesta correcta (Type %u, Code %u)\n", tipo, codigo);
		else	printf("%s (Type %u, Code %u)\n", errores (tipo, codigo), tipo, codigo);
	}
	
	// En caso de que se escedan los 10 segundos sin usar el socket
	else printf("Timeout: No se ha recibido respuesta en 10 segundos\n");
	
	// Se cierra el socket
	close(sock);
	return 0;

}

unsigned int calculoChecksum (){
	// Se declaran las variable
	int i;
	unsigned short int *puntero = (unsigned short int*) &datagrama;
	unsigned int acumulador = 0;

	// Se calcula el checksum
	for (i = 0; i < sizeof(datagrama)/2; i++){
		acumulador += (unsigned int) *puntero;
		puntero++;
	}

	acumulador = (acumulador >> 16) + (acumulador & 0x0000ffff);
	acumulador = (acumulador >> 16) + (acumulador & 0x0000ffff);

	return (~acumulador);
}

char* errores(unsigned char type, unsigned char code){
	switch (type){
		case 3:
			switch(code){
				case 0:
					return "Destination Unreachable: Net Unreachable";
				case 1:
					return "Destination Unreachable: Host Unreachable";
				case 2:
					return "Destination Unreachable: Protocol Unreachable";
				case 3:
					return "Destination Unreachable: Port Unreachable";
				case 4:
					return "Destination Unreachable: Fragmentatio Needed";
				case 5:
					return "Destination Unreachable: Source Route Failed";
				case 6:
					return "Destination Unreachable: Destination Network Unknown";
				case 7:
					return "Destination Unreachable: Destination Host Unknown";
				case 8:
					return "Destination Unreachable: Source Host Isolated";
				case 11:
					return "Destination Unreachable: Destination Network Unreacheable for Type of Service";
				case 12:
					return "Destination Unreachable: Destination Host Unreachable for Type of Service";
				case 13:
					return "Destination Unreachable: Communication Administratively Prohibited";
				case 14:
					return "Destination Unreachable: Host Precedence Violation";
				case 15:
					return "Destination Unreachable: Precedence Cutoff in Effect";
				default:
				       	return "Destination Unreachable: Error desconocido";
			}
		case 5:
			switch(code){
				case 1:
					return "Redirect: Redirect for Destination Host";
				case 3:
					return "Redirect: Redrect for Destination Host Based on Type-of-Service";
				default:
					return "Redirect: Error desconocido";
			}
		case 11:
			switch(code){
				case 0:
					return "Time Exceeded: Time-to-Live Exceeded in Transit";
				case 1:
					return "Time Exceeded: Fragment Reassembly Time Exceeded";
				default:
					return "Time Exceeded: Error desconocido";
			}
		case 12:
			switch(code){
				case 0:
					return "Parameter Problem: Pointer indicates the error";
				case 1:
					return "Parameter Problem: Missing a Requiered Optino";
				case 2:
					return "Parameter Problem: Bad Length";
				default:
					return "Parameter Problem: Error deconocido";
			}
		default:
			return "Error de tipo desconocido";
	}
}
