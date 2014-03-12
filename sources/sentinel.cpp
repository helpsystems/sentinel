/****************************************************************************/

/* 
 * Copyright 2014 Core Security Technologies.
 * 
 * This file is part of Sentinel, an exploit mitigation tool.
 * Sentinel was designed and developed by Nicolas Economou, from the
 *  Exploit Writers team of Core Security Technologies.
 *
 * This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 3
 *  as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * For further details, see the file COPYING distributed with Sentinel.
 */

/****************************************************************************/

/* Sentinel Interface */

/****************************************************************************/

#include <windows.h>
#include <stdio.h>
#include <winsock2.h>
#include <tlhelp32.h>

#include "list.cpp"
#include "string.cpp"

/****************************************************************************/

/* Prototipos */

void process_communication ( HANDLE , HANDLE , unsigned int , char ** );
int waiting_for_processes ( List & , List & );
int parse_process_list ( char * , List & , List & );
int GetNextPid ( List & , unsigned int * );
int GetNextProcess ( PROCESSENTRY32 * );

HANDLE OpenProcessWithPrivileges ( int , int , int );
int read_memory ( HANDLE , void * , unsigned int , unsigned char * , unsigned int * );
int write_memory ( HANDLE , void * , unsigned int , unsigned char * , unsigned int * );
int open_tcp_port ( char * , SOCKET * , unsigned int * );
void *inject_shellcode ( HANDLE , HANDLE , unsigned int , char * );

unsigned int get_loader ( HANDLE , char ** , char * );
__declspec ( naked ) void loader0 ( void );
void loader ( void );
char *get_sentinel_string ( void );
char *get_sentinel_pipe ( void );

//int send_command ( HANDLE , unsigned int , unsigned int , unsigned char * );
int send_command ( SOCKET , unsigned int , unsigned int , unsigned char * );
//int recv_command ( HANDLE , unsigned int * , unsigned int * , unsigned char * );
int recv_command ( SOCKET , unsigned int * , unsigned int * , unsigned char * );

void loader_end ( void );

/****************************************************************************/

unsigned int sentinel_port;

/****************************************************************************/


int main ( int argc , char *argv [] )
{
  STARTUPINFO startupinfo;
  PROCESS_INFORMATION pinf;
  HANDLE thandle = NULL;
  HANDLE phandle;
  List processes;
  List lines;
  String *process;
  String *line;
  char params [ 4096 ];
  unsigned int cont;
  int tid = 0;
  int pid;
  int ret;

/* Controlo los argumentos */
  if ( argc < 3 )
  {
    printf ( "\nSentinel v0.9.3 beta\n" );
    printf ( "Created by Nicolas A. Economou\n" );
    printf ( "Core Security Technologies, Buenos Aires, Argentina (2014)\n" );
    printf ( "\nuse: sentinel <-p pid|-e executable|-pn process_name|-pl filename> [module_to_protect [module_to_protect [...]]]\n" );
    return ( 0 );
  }
/* Si estan los 3 o 4 argumentos */
  else
  {
  /* Si los argumentos NO son correctos */
    if ( ( strcmp ( argv [ 1 ] , "-p" ) != 0 ) && ( strcmp ( argv [ 1 ] , "-e" ) != 0 ) && ( strcmp ( argv [ 1 ] , "-pn" ) != 0 ) && ( ( strcmp ( argv [ 1 ] , "-pl" ) && ( argc == 3 ) ) != 0 ) ) 
    {
      printf ( "\nSentinel v0.9.3 beta\n" );
      printf ( "Created by Nicolas A. Economou\n" );
      printf ( "Core Security Technologies, Buenos Aires, Argentina (2014)\n" );
      printf ( "\nuse: sentinel <-p pid|-e executable|-pn process_name|-pl filename> [module_to_protect [module_to_protect [...]]]\n" );
      return ( 0 );
    }
  }

/* Si tengo que ejecutarlo */
  if ( strcmp ( argv [ 1 ] , "-e" ) == 0 )
  {
  /* Seteo la estructura inicial */
    memset ( &startupinfo , 0 , sizeof ( STARTUPINFO ) );
    startupinfo.cb = sizeof ( startupinfo );
    startupinfo.dwFlags = STARTF_USESHOWWINDOW;
    startupinfo.wShowWindow = SW_SHOW;

  /* Ejecuto el proceso */
    ret = CreateProcess ( argv [ 2 ] , NULL , NULL , NULL , FALSE , CREATE_SUSPENDED , NULL , NULL , &startupinfo , &pinf );
//    printf ( "ret = %i\n" , ret );
//    printf ( "pid = %i\n" , pinf.dwProcessId );

  /* Si el proceso NO pudo ser abierto */
    if ( ret == FALSE )
    {
      printf ( "process error !!!\n" );  
      return ( 0 );
    }

  /* Activo el proceso */
//    ret = ResumeThread ( pinf.hThread );
//    printf ( "ret = %i\n" , ret );

  /* PID */
//    pid = pinf.dwProcessId;

  /* Handle del proceso */
    phandle = pinf.hProcess;

  /* Handle del thread */
    thandle = pinf.hThread;
  }
/* Si tengo que proteger TODOS los procesos con el MISMO NOMBRE */
  else if ( strcmp ( argv [ 1 ] , "-pn" ) == 0 )
  {
  /* Mensaje al usuario */
    printf ( "\n" );
    printf ( "[x] Sentinel working ...\n" );
    printf ( "[x] Monitor mode activated (press CTRL+C to finish)\n" );

  /* Si el proceso a proteger es SENTINEL */
    if ( stricmp ( argv [ 2 ] , "sentinel.exe" ) == 0 )
    {
      printf ( "[ ] Error: Sentinel can't protect itself ...\n" );
      return ( 0 );
    }

  /* Inicializo los parametros a pasar a sentinel */
    strcpy ( params , "" );

  /* Armo la linea de ejecucion */
    for ( cont = 3 ; cont < argc ; cont ++ )
    {
    /* Si es el primer parametro */
      if ( cont == 3 )
      {
      /* Inicializo el string */
        strncat ( params , argv [ 3 ] , sizeof ( params ) );
      }
    /* Si es el resto de los modulos a proteger */
      else
      {
      /* Pongo un espacio entre los argumentos */
        strncat ( params , " " , sizeof ( params ) );

      /* Agrego el siguiente parametro */
        strncat ( params , argv [ cont ] , sizeof ( params ) );
      }
    }

  /* Creo el string para pasar a Sentinel */
    process = new ( String );
    line = new ( String );

  /* Seteo el proceso a proteger */
    process -> Set ( argv [ 2 ] );
    line -> Set ( params );

  /* Armo las listas */
    processes.Add ( ( void * ) process );
    lines.Add ( ( void * ) line );

  /* Empiezo a attacharme a todos los procesos */
    waiting_for_processes ( processes , lines );

  /* Salgo */
    return ( 1 );
  }
/* Si tengo que proteger una LISTA de procesos */
  else if ( strcmp ( argv [ 1 ] , "-pl" ) == 0 )
  {
  /* Mensaje al usuario */
    printf ( "\n" );
    printf ( "[x] Sentinel working ...\n" );
    printf ( "[x] Parsing process list '%s'\n" , argv [ 2 ] );

  /* Empiezo a attacharme a todos los procesos */
    ret = parse_process_list ( argv [ 2 ] , processes , lines );

  /* Si la LISTA DE PROCESOS pudo ser PARSEADA */
    if ( ret == TRUE )
    {
    /* Mensaje al usuario */
      printf ( "[x] Done\n\n" );
      printf ( "[x] Monitor mode activated (press CTRL+C to finish)\n" );

    /* Empiezo a attacharme a todos los procesos */
      waiting_for_processes ( processes , lines );
    }

  /* Salgo */
    return ( 1 );
  }
/* Si el proceso ya esta corriendo */
  else
  {
  /* PID */
    pid = atoi ( argv [ 2 ] );

  /* Abro el proceso */
    if ( ( phandle = OpenProcessWithPrivileges ( PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE  , FALSE ,  pid ) ) == NULL )
    {
      printf ( "process error !!!\n" );  
      return ( 0 );
    }
  }

/* Establezco la comunicacion con el proceso */
  process_communication ( phandle , thandle , argc - 3 , &argv [ 3 ] );  

  return ( 1 );
}

/****************************************************************************/

void process_communication ( HANDLE phandle , HANDLE thandle , unsigned int modules_to_protect , char **modules )
{
  HANDLE sentinel_thandle;
//  HANDLE pipe;
  struct sockaddr_in saddrin;
  char sentinel_pipe [ 256 ];
  char module_list [ 1024 ];
  char msg [ 1024 ];
  char cmd [ 1024 ];
  char title [ 256 ];
  char *shellcode;
  unsigned int addr_protection_activated;
  unsigned int leidos;
  unsigned int escritos;
  unsigned int title_size;
  unsigned int msg_size;
  unsigned int operation_size;
  unsigned int operation_id;
  unsigned int pusher;
  unsigned int poper;
  unsigned int size;
  unsigned int cont;
  unsigned int pid;
  unsigned int tid;
  int process_running = TRUE;
  int ret_id;
  int ret;
  SOCKET pipe;
  SOCKET sock;
  int len;

/* Armo el nombre del PIPE a conectarse */
//  sprintf ( sentinel_pipe , "\\\\.\\pipe\\sentinel_%.8x" , GetTickCount () );
//  printf ( "\n[x] Connection PIPE: %s\n" , sentinel_pipe );

/* Creo un PIPE para hablar con el proceso que estoy protegiendo */
//  pipe = CreateNamedPipe ( sentinel_pipe , PIPE_ACCESS_DUPLEX , PIPE_TYPE_BYTE , 1 , 4096 , 4096 , 0 , NULL );
//  printf ( "%x\n" , pipe );

/* Espero que el proceso se me conecte */
//  ret = ConnectNamedPipe ( pipe , NULL );
//  printf ( "connected = %x\n" , ret );

/* Si ningun puerto pudo ser abierto */
  if ( open_tcp_port ( "127.0.0.1" , &sock , &sentinel_port ) == FALSE )
  { 
    printf ( "[x] Error: Any TCP port couldn't be opened\n" );
    return;
  }

/////////////////

/* Inyecto Sentinel en el proceso */

/* Alloco memoria para el shellcode */
//  shellcode = ( char * ) malloc ( ( unsigned int ) loader_end - ( unsigned int ) loader );

/* Obtengo el LOADER a inyectar */
  size = get_loader ( thandle , &shellcode , sentinel_pipe );

/* Inyecto el loader */
  inject_shellcode ( phandle , thandle , size , shellcode );

/////////////////

/* Espero que el proceso se me conecte */
  len = sizeof ( struct sockaddr );
  pipe = accept ( sock , ( struct sockaddr * ) &saddrin , &len );

/* Espero que Sentinel me pida que lo proteja */
  recv_command ( pipe , &operation_id , &operation_size , msg );

/* Si recibi el comando "PROTECT ME" */
  if ( operation_id == 0x80000001 )
  {
  /* Mando el OK para que Sentinel se quede loopeando */
    send_command ( pipe , operation_id , 4 , "okok" );

  /* Obtengo los valores */
    pid = * ( unsigned int * ) &msg [ 0x0 ];
    tid = * ( unsigned int * ) &msg [ 0x4 ];
    pusher = * ( unsigned int * ) &msg [ 0x8 ];
    poper = * ( unsigned int * ) &msg [ 0xc ];
    addr_protection_activated = * ( unsigned int * ) &msg [ 0x10 ];

  /* Protejo al binario */  
//    printf ( "pid = %i\n" , pid );
//    printf ( "pusher = %x\n" , pusher );
//    printf ( "poper = %x\n" , poper );

  /* Abro el thread de Sentinel */
     sentinel_thandle = OpenThread ( THREAD_SUSPEND_RESUME , FALSE , tid );

  /* Suspendo el thread de Sentinel */
     SuspendThread ( sentinel_thandle );

  /* Inicializo el string */
     strcpy ( module_list , "" );

  /* Armo la lista de modulos a proteger */
    for ( cont = 0 ; cont < modules_to_protect ; cont ++ )
    {
    /* Si NO es la primera vez */
      if ( cont > 0 )
      {
      /* Agrego un separador */
        strncat ( module_list , " " , 1023 );
      }

    /* Agrego el siguiente modulo */
      strncat ( module_list , modules [ cont ] , 1023 );
    }

  /* Armo la linea a ejecutar */
    snprintf ( cmd , 1023 , "protector.exe %i %x %x %s" , pid  , pusher , poper , module_list ); 

  /* Protejo a la aplicacion */
    system ( cmd );

  /* Mando el OK */
//    send_command ( pipe , operation_id , 4 , "okok" );

  /* Seteo en TRUE la variable para que siga corriendo */
    write_memory ( phandle , ( void * ) addr_protection_activated , 1 , "\x01" , &escritos );

  /* Si el proceso fue levantado desde cero */
//    if ( thandle != NULL )
//   {
//    /* Activo el thread principal */
//      ret = ResumeThread ( thandle );
//    }

  /* Activo el thread de Sentinel */
    ResumeThread ( sentinel_thandle );
  }
  else
  {
    printf ( "unexpected command\n" );
    exit ( 0 );
  }

/* Mientras el proceso siga corriendo */
  while ( process_running == TRUE )
  {
  /* Inicializo el codigo de operacion ( para evitar errores ) */
    operation_id = 0;

  /* Espero un mensaje del cliente */
    recv_command ( pipe , &operation_id , &operation_size , title );

  /* Si es un mensaje para el usuario */
    if ( operation_id == 0x80000002 )
    {
    /* Recibo el mensaje */
      recv_command ( pipe , &operation_id , &operation_size , msg );

    /* Imprimo el mensaje */
//      ret_id = MessageBox ( NULL , msg , title , MB_YESNO | MB_ICONWARNING | MB_TOPMOST );
//      ret_id = MessageBox ( NULL , msg , title , MB_YESNO | MB_ICONWARNING | MB_SERVICE_NOTIFICATION );
      ret_id = MessageBox ( NULL , msg , title , MB_YESNO | MB_ICONERROR | MB_SERVICE_NOTIFICATION );

    /* Envio la respuesta al proceso */
      send_command ( pipe , operation_id , sizeof ( ret_id ) , ( unsigned char * ) &ret_id );
    }
  /* Mensaje desconocido */
    else
    {
      printf ( "[x] Connection closed\n" );
      process_running = FALSE;
    }
  }
}

/****************************************************************************/

int waiting_for_processes ( List &processes , List &lines )
{
  STARTUPINFO si;
  PROCESS_INFORMATION pi;
  List new_pids;
  List pids;
  String *process;
  String *line;
  char cmd [ 4096 ];
  unsigned int cont;
  unsigned int pos;
  int first_time = TRUE;
  int ret = TRUE;
  int pid;

/* Espero a que aparezcan NUEVAS instancias del proceso */
  while ( 1 )
  {
  /* Listo todos los procesos */
    pid = GetNextPid ( processes , &pos );

  /* Si obtuve un PID valido */
    if ( pid != -1 )
    {
    /* Agrego el PID a la lista de CURRENTS */
      new_pids.Add ( ( void * ) pid );

    /* Si NO fue protegido */
      if ( pids.Find ( ( void * ) pid ) == FALSE )
      {
      /* Proceso a proteger */
        process = ( String * ) processes.Get ( pos );

      /* Mensaje al usuario */
        printf ( "[x] New process found: '%s' - pid %i\n" , process -> Get () , pid );

      /* Si ya recorri la lista de procesos mas de una vez */
        if ( first_time == FALSE )
        {
        /* Hago una demora hasta que el proceso de inicialize */
          Sleep ( 1000 );
        }

      /* Obtengo los modulos a PROTEGER para este proceso */
        line = ( String * ) lines.Get ( pos );

      /* Armo la linea a ejecutar */
        snprintf ( cmd , sizeof ( cmd ) , "%s -p %i %s" , "sentinel.exe" , pid , line -> Get () );

      /* Inicializo la estructura inicial */
        memset ( &si , 0 , sizeof ( si ) );
        si.cb = sizeof ( si );
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_MINIMIZE;

      /* Protejo al proceso */
        CreateProcess ( NULL , cmd , NULL , NULL , NULL , CREATE_NEW_CONSOLE , NULL , NULL , &si , &pi );

      /* Lo agrego a la lista */
        pids.Add ( ( void * ) pid );
      }

    /* Paso al siguiente */
      continue;
    }
  /* Si la lista de procesos llego hasta el fin */
    else
    {
    /* Actualizo la lista de procesos que estan CORRIENDO */
      pids.Clear ();
      pids.Append ( new_pids );

    /* Re-inicializo la lista */
      new_pids.Clear ();

    /* De ahora en mas, espero 1 segundo a que se inicialize el proceso */
      first_time = FALSE;
    }

  /* Espero X cantidad de tiempo antes de listar los procesos de nuevo */
    Sleep ( 1000 );
  }

  return ( ret );
}

/****************************************************************************/

int parse_process_list ( char *process_list , List &processes , List &lines )
{
  STARTUPINFO si;
  PROCESS_INFORMATION pi;
  List myprocesses;
  List mylines;
  String *cmdline;
  String *cmdline2;
  String *process;
  String *process2;
  unsigned int cont, cont2;
  char cmd [ 4096 ];
  char line [ 1024 ];
  int valid_line;
  int ret = TRUE;
  FILE *f;
  char *p;

/* Abro la lista de procesos */
  f = fopen ( process_list , "rt" );

/* Si el archivo existe */
  if ( f != NULL )
  {
  /* Proceso linea por linea */
    while ( fgets ( line , sizeof ( line ) , f ) != 0 )
    {
    /* Si el ultimo caracter es un ENTER */
      if ( line [ strlen ( line ) - 1 ] == '\n' )
      {
      /* Elimino el ENTER */
        line [ strlen ( line ) - 1 ] = '\x00';
      }

    /* Saco todos los espacios al principio de la linea */
      p = line;

    /* Mientras haya espacios */
      while ( *p == ' ' )
      {
      /* Avanzo al siguiente caracter */
        p ++;
      }

    /* Si hay algun espacio adelante del nombre del proceso */
      if ( line != p )
      {
      /* Elimino los espacios delante del string */
        strcpy ( line , p );
      }

    /* Si hay un proceso a proteger */
      if ( strlen ( line ) > 0 )
      {
      /* Si NO es un COMENTARIO */
        if ( line [ 0 ] != '#' )
        {
        /* Obtengo el proceso a proteger */
          p = strtok ( line , " " );

        /* Proceso a PROTEGER */
          process = new ( String );
          process -> Set ( p );
          myprocesses.Add ( ( void * ) process );

        /* Obtengo los modulos a proteger del programa */
          p = strtok ( NULL , "" );
          cmdline = new ( String );

        /* Si hay modulos que proteger */
          if ( p != NULL )
          {
          /* Linea a ejecutar */
            cmdline -> Set ( p );
          }
        /* Si NO hay modulos que proteger */
          else
          {
          /* Linea a ejecutar */
            cmdline -> Set ( "" );
          }

        /* Lista de procesos a PROTEGER */
          mylines.Add ( ( void * ) cmdline );
        }
      }
    }

  /* Cierro el archivo */
    fclose ( f );

  /* Procesos a proteger */
    for ( cont = 0 ; cont < myprocesses.Len () ; cont ++ )
    {
    /* Levanto el siguiente proceso */
      process = ( String * ) myprocesses.Get ( cont );

    /* Flag para saber si la linea a ejecutar es VALIDA */
      valid_line = TRUE;

    /* Si estoy tratando de proteger a SENTINEL */
      if ( stricmp ( process -> Get () , "sentinel.exe" ) == 0 )
      {
      /* Mensaje al usuario */
        printf ( "[ ] Error: Sentinel can't protect itself ...\n" );

      /* Paso a la siguiente linea */
        continue;
      }

    /* Recorro el resto de las lineas */
      for ( cont2 = cont + 1 ; cont2 < myprocesses.Len () ; cont2 ++ )
      {
      /* Levanto la siguiente linea */
        process2 = ( String * ) myprocesses.Get ( cont2 );

      /* Si estoy tratando de progeter otra vez al mismo proceso */
        if ( stricmp ( process -> Get () , process2 -> Get () ) == 0 )
        {
        /* Mensaje al usuario */
          printf ( "[ ] Error: Repetead line %i\n" , cont + 1 );

        /* No puedo ejecutar esta linea */
          valid_line = FALSE;

        /* Paso a la siguiente linea */
          break;
        }
      }

    /* Si puedo proteger a este proceso */
      if ( valid_line == TRUE )
      {
      /* Otro proceso a PROTEGER */      
        processes.Add ( ( void * ) process );
        lines.Add ( mylines.Get ( cont ) );
      }
    }
  }
/* Si el file no pudo ser abierto */
  else
  {
  /* Mensaje al usuario */
    printf ( "[ ] Error: Invalid process list file\n" );

  /* Salgo con ERROR */
    ret = FALSE;
  }

  return ( ret );
}

/****************************************************************************/

HANDLE OpenProcessWithPrivileges ( int access , int inherite , int pid )
{
  TOKEN_PRIVILEGES new_token_privileges;
  unsigned int token_handle;
  HANDLE ret;

/* Pido permiso como debugger */
  LookupPrivilegeValueA ( NULL , SE_DEBUG_NAME , &new_token_privileges.Privileges [ 0 ].Luid );

/* Abro el token */
  OpenProcessToken ( GetCurrentProcess () , TOKEN_ADJUST_PRIVILEGES , ( void ** ) &token_handle );

/* Nuevos valores de privilegio */
  new_token_privileges.PrivilegeCount = 1;
  new_token_privileges.Privileges [ 0 ].Attributes = SE_PRIVILEGE_ENABLED;

/* Ajusto los privilegios */
  AdjustTokenPrivileges ( ( void * ) token_handle , FALSE , &new_token_privileges , sizeof ( new_token_privileges ) , NULL , NULL );

/* Abro el proceso */
  ret = OpenProcess ( access , inherite , pid );

  return ( ret );
}

/****************************************************************************/

int GetNextPid ( List &processes , unsigned int *pos )
{
  PROCESSENTRY32 process;
  unsigned int cont;
  int pid = -1;
  String *pname;

/* Listo todos los procesos que faltan */
  while ( GetNextProcess ( &process ) == TRUE )
  {
  /* Recorro TODOS los procesos a proteger */
    for ( cont = 0 ; cont < processes.Len () ; cont ++ )
    {
    /* Levanto el siguiente PROCESO a PROTEGER */
      pname = ( String * ) processes.Get ( cont );

    /* Si es el proceso que estoy buscando */
      if ( stricmp ( pname -> Get () , process.szExeFile ) == 0 )
      {
      /* Retorno este PID */
        pid = process.th32ProcessID;

      /* Para saber que proceso es */
        *pos = cont;

      /* Dejo de listar */
        return ( pid );
      }
    }
  }

  return ( pid );
}

/****************************************************************************/

int GetNextProcess ( PROCESSENTRY32 *process )
{
  static HANDLE handle = NULL;
  int ret = FALSE;

/* Si estoy empezando un request nuevo */
  if ( handle == NULL )
  {
  /* Imagen del sistema */
    handle = CreateToolhelp32Snapshot ( TH32CS_SNAPALL , 0 );

  /* Inicializo la estructura */
    process -> dwSize = sizeof ( PROCESSENTRY32 );

  /* Listo el siguiente proceso */
    ret = Process32First ( handle , process );
  }
  else
  {
  /* Listo el siguiente proceso */
    ret = Process32Next ( handle , process );
  }

/* Si ya liste todos los procesos */
  if ( ret == FALSE )
  {
  /* Cierro el HANDLE del Snapshot */
    CloseHandle ( handle );

  /* Dejo preparada la funcion para otro request */
    handle = NULL;
  }

  return ( ret );
}

/*************************************************************/

int read_memory ( HANDLE phandle , void *address , unsigned int size , unsigned char *buffer , unsigned int *leidos )
{
  int ret;

/* Leo memoria */
  ret = ReadProcessMemory ( phandle , address , ( void * ) buffer , size , ( DWORD * ) leidos );

  return ( ret );
}

/*************************************************************/

int write_memory ( HANDLE phandle , void *address , unsigned int size , unsigned char *buffer , unsigned int *escritos )
{
  int ret;

/* Escribo memoria */
  ret = WriteProcessMemory ( phandle , address , ( void * ) buffer , size , ( DWORD * ) escritos );

  return ( ret );
}

/****************************************************************************/

int open_tcp_port ( char *ip , SOCKET *new_sock , unsigned int *port )
{
  struct sockaddr_in saddr;
  SOCKET sock;
  WORD wRequestedVersion;
  WSADATA wsaData;
  unsigned int cont;
  int ret = FALSE;

/* Inicializo la lib de sockets */
  wRequestedVersion = 0x0202;
  WSAStartup ( wRequestedVersion , &wsaData );

/* Creo el socket */
  sock = socket ( AF_INET , SOCK_STREAM , 0 );

/* Pruebo si hay algun puerto libre */
  for ( cont = 50000 ; cont <= 65535 ; cont ++ )
  {
  /* Tipo de socket a crear */
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = inet_addr ( "127.0.0.1" );
    saddr.sin_port = htons ( ( unsigned short ) cont );     

  /* Preparo el socket para aceptar conexiones */
    ret = bind ( sock , ( struct sockaddr * ) &saddr , sizeof ( struct sockaddr ) );

  /* Si el puerto pudo ser abierto */
    if ( ret == 0 )
    {
    /* Cantidad de conexiones a aceptar */
      listen ( sock , 0 );

    /* Retorno el socket creado */
      *new_sock = sock;

    /* Retorno el puerto TCP abierto */
      *port = cont;

    /* Retorno OK */
      ret = TRUE;

    /* Dejo de probar */
      break;
    }
  }

  return ( ret );
} 

/****************************************************************************/

void *inject_shellcode ( HANDLE phandle , HANDLE thandle , unsigned int size , char *shellcode )
{
  CONTEXT thread_context;
  unsigned int bytes_escritos;
  unsigned int original_eip;
  void *address;
  int res;

/* Reservo memoria en el proceso para inyectar el codigo */
  if ( ( ( void * ) address = VirtualAllocEx ( phandle , ( void * ) NULL , size , MEM_COMMIT , PAGE_EXECUTE ) ) == NULL )
  {
    printf ( "allocate memory error !!!\n" );  
    return ( NULL );
  }

/* Escribo en la memoria del proceso el codigo */
  if ( WriteProcessMemory ( phandle , ( void * ) address , shellcode , size , ( DWORD * ) &bytes_escritos ) == NULL )
  {
    printf ( "write memory error !!!\n" );  
    return ( NULL );
  }

/* Direccion donde aloco el bloque */
//  printf ( "shellcode address = %x\n" , address );

/* Si el proceso ya estaba corriendo */
  if ( thandle == NULL )
  {
  /* Creo un thread en el proceso */
    if ( CreateRemoteThread ( phandle , NULL , 0 , ( LPTHREAD_START_ROUTINE ) address , NULL , 0 , NULL ) == NULL )
    {
      printf ( "create remote thread error !!!\n" );
      return ( NULL );
    }
  }
/* Si el proceso acaba de ser lanzado */
  else
  {
  /* Armo un TRAMPOLINE AL LOADER */

  /* El tipo de contexto que necesito */
    thread_context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS | CONTEXT_FLOATING_POINT | CONTEXT_EXTENDED_REGISTERS;

  /* Obtengo el contexto */
    res = GetThreadContext ( thandle , &thread_context );
//    printf ( "res = %i\n" , res );

  /* Obtengo la direccion inicial de EIP */
    original_eip = thread_context.Eip;

  /* Pusheo el valor inicial de EIP para que retorne a esa direccion */
    thread_context.Esp = thread_context.Esp - 4;

  /* Escribo el RETURN ADDRESS */
    WriteProcessMemory ( phandle , ( void * ) thread_context.Esp , &original_eip , sizeof ( original_eip ) , ( DWORD * ) &bytes_escritos );

  /* Redirijo la ejecucion del thread */
    thread_context.Eip = ( unsigned int ) address;

  /* Seteo el contexto */
    SetThreadContext ( thandle , &thread_context );   

  /* Resumo el thread */
    ResumeThread ( thandle );
  }

  return ( address );
}

/****************************************************************************/

unsigned int get_loader ( HANDLE thandle , char **shellcode_to_inject , char *sentinel_pipe )
{
  unsigned int size = 0;
  char *shellcode;
  char *p;

/* Si el proceso es lanzado desde el principio */
  if ( thandle != NULL )
  {
  /* Longitud del shellcode */
    size = ( unsigned int ) loader_end - ( unsigned int ) loader0;

  /* Alloco memoria para el shellcode */
    shellcode = ( char * ) malloc ( size );

  /* Escribo el shellcode en el buffer */
    memcpy ( shellcode , ( void * ) loader0 , size );
  }
  else
  {
  /* Longitud del shellcode */
    size = ( unsigned int ) loader_end - ( unsigned int ) loader;

  /* Alloco memoria para el shellcode */
    shellcode = ( char * ) malloc ( size );

  /* Escribo el shellcode en el buffer */
    memcpy ( shellcode , ( void * ) loader , size );
  }

//  printf ( "size = %i\n" , size );

/* Retorno la direccion del SHELLCODE ALLOCADO */
  *shellcode_to_inject = shellcode;

//////////////

/* Apunto al principio del shellcode */
  p = shellcode;

/* Busco el valor 0x33333333 */
  while ( 1 )
  {
  /* Si es el valor que estoy buscando */
    if ( * ( unsigned int * ) p == 0x33333333 )
    {
    /* Patcheo el puntero */
      * ( unsigned int * ) p = ( unsigned int ) GetProcAddress ( GetModuleHandle ( "kernel32.dll" ) , "LoadLibraryA" );

    /* Dejo de buscar */
      break;
    }
    else
    {
    /* Avanzo en el shellcode */
      p ++;
    }
  }

//////////////

/* Apunto al principio del shellcode */
  p = shellcode;

/* Busco la cookie con para poner el PATH */
  while ( 1 )
  {
  /* Si es el valor que estoy buscando */
    if ( strncmp ( p , "sentinel_pathname" , 17 ) == 0 )
    {
    /* Seteo el path donde esta ubicado Sentinel.dll */
      GetFullPathName ( "Sentinel.dll" , 1024 , p , NULL );

    /* Dejo de buscar */
      break;
    }
    else
    {
    /* Avanzo en el shellcode */
      p ++;
    }
  }

//////////////

/* Apunto al principio del shellcode */
  p = shellcode;

/* Busco el valor 0x44444444 */
  while ( 1 )
  {
  /* Si es el valor que estoy buscando */
    if ( * ( unsigned int * ) p == 0x44444444 )
    {
    /* Patcheo el puntero */
      * ( unsigned int * ) p = ( unsigned int ) sentinel_port;

    /* Dejo de buscar */
      break;
    }
    else
    {
    /* Avanzo en el shellcode */
      p ++;
    }
  }

//////////////

  return ( size );
}

/***************************************************************************/

//int send_command ( HANDLE sentinel_server , unsigned int command_id , unsigned int size , unsigned char *buffer )
//{
//  unsigned long int escritos;
//  unsigned long int leidos;
//  int ret = FALSE;
//
///* Mando el ID del comando */
//  WriteFile ( sentinel_server , &command_id , sizeof ( command_id ) , &escritos , NULL );
//
///* Mando el size del comando */
//  WriteFile ( sentinel_server , &size , sizeof ( size ) , &escritos , NULL );
//
///* Mando la DATA */
//  WriteFile ( sentinel_server , buffer , size , &escritos , NULL );
//
//  return ( ret );
//}

/***************************************************************************/

int send_command ( SOCKET sentinel_server , unsigned int command_id , unsigned int size , unsigned char *buffer )
{
  unsigned int escritos;
  int ret = FALSE;

/* Mando el ID del comando */
//  WriteFile ( sentinel_server , &command_id , sizeof ( command_id ) , &escritos , NULL );
  escritos = send ( sentinel_server , ( const char * ) &command_id , sizeof ( command_id ) , 0 );

/* Mando el size del comando */
//  WriteFile ( sentinel_server , &size , sizeof ( size ) , &escritos , NULL );
  escritos = send ( sentinel_server , ( const char * ) &size , sizeof ( size ) , 0 );

/* Mando la DATA */
//  WriteFile ( sentinel_server , buffer , size , &escritos , NULL );
  escritos = send ( sentinel_server , ( const char * ) buffer , size , 0 );

  return ( ret );
}

/***************************************************************************/

//int recv_command ( HANDLE sentinel_server , unsigned int *command_id , unsigned int *size , unsigned char *buffer )
//{
//  unsigned long int escritos;
//  unsigned long int leidos;
//  int ret = TRUE;
//
///* Espero el ID del comando */
//  ReadFile ( sentinel_server , command_id , sizeof ( unsigned int * ) , &leidos , NULL );
//
///* Espero el size del comando */
//  ReadFile ( sentinel_server , size , sizeof ( unsigned int * ) , &leidos , NULL );
//
///* Espero el comando */
//  ReadFile ( sentinel_server , buffer , *size , &leidos , NULL );
//
//  return ( ret );
//}

/***************************************************************************/

int recv_command ( SOCKET sentinel_server , unsigned int *command_id , unsigned int *size , unsigned char *buffer )
{
  unsigned int leidos;
  int ret = TRUE;

/* Espero el ID del comando */
//  ReadFile ( sentinel_server , command_id , sizeof ( unsigned int * ) , &leidos , NULL );
  leidos = recv ( sentinel_server , ( char * ) command_id , sizeof ( unsigned int * ) , 0 );

/* Espero el size del comando */
//  ReadFile ( sentinel_server , size , sizeof ( unsigned int * ) , &leidos , NULL );
  leidos = recv ( sentinel_server , ( char * ) size , sizeof ( unsigned int * ) , 0 );

/* Espero el comando */
//  ReadFile ( sentinel_server , buffer , *size , &leidos , NULL );
  leidos = recv ( sentinel_server , ( char * ) buffer , *size , 0 );

  return ( ret );
}

/****************************************************************************/

__declspec ( naked ) void loader0 ( void )
{
/* Salvo todos los registros */
  asm pushfd
  asm pushad

/* Para que NO salten los chequeos mientras se inicializa Sentinel */
  asm mov dword ptr fs:[0xff8],1

/* Carga Sentinel */
  loader ();

/* Para que NO salten los chequeos mientras se inicializa Sentinel */
  asm mov dword ptr fs:[0xff8],0

/* Restauro todos los registros */
  asm popad
  asm popfd

/* Retorno al ENTRY POINT del programa */
  asm ret
}

/****************************************************************************/

void loader ( void )
{
  void *WINAPI ( *myLoadLibrary ) ( char * );
  unsigned int sentinel_port;

/* Puntero a rellenar */
  ( void * ) myLoadLibrary = ( void * ) 0x33333333;

/* Valor a setear */
  sentinel_port = 0x44444444;

/* Seteo la TEB con el valor del PORT a conectarse */
//  _EAX = ( unsigned int ) get_sentinel_port ();
  _EAX = sentinel_port;
  asm mov dword ptr fs:[0xffc],eax

/* Cargo la lib de sentinel */
  myLoadLibrary ( get_sentinel_string () );

/* Salgo */
//  mySleep ( 66666666 );

/* Breakpoint para disparar el debugger */
//  asm int 3
}

/****************************************************************************/

char *get_sentinel_string ( void )
{
  asm call salir
  asm db 'sentinel_pathname'
  asm db 1024 dup ( 0 )

  asm salir:;
  asm pop eax

  return ( ( char * ) _EAX );  
}

/****************************************************************************/

char *get_sentinel_port ( void )
{
  asm call salir2
  asm db 'sentinel_port'
  asm db 256 dup ( 0 )

  asm salir2:;
  asm pop eax

  return ( ( char * ) _EAX );  
}

/****************************************************************************/

void loader_end ( void )
{
}

/****************************************************************************/
/****************************************************************************/
