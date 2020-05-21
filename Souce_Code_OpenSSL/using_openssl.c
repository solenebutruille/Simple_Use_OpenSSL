#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#define TAILLE_MAX 1000 // Tableau de taille 1000

/* A 256 bit key */
unsigned char *key_256 = (unsigned char *)"7384925283925097301753540283638";
unsigned char *key_128 = (unsigned char *)"0123456789012745";
unsigned char *key_168 = (unsigned char *)"012345678901274543";
unsigned char *aad = (unsigned char *)"0123456789012745";
  /* A 128 bit IV */
  unsigned char *iv = (unsigned char *)"0123456789012345";
  unsigned char *iv_7 = (unsigned char *)"7653456";

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len,
            unsigned char *iv, unsigned char *ciphertext, int parameters)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     */
     int test = -10;
     switch (parameters) {
       case 1: test =  EVP_EncryptInit_ex(ctx, EVP_des_ede_cbc(), NULL, key_168, iv); break;
       case 2: test =  EVP_EncryptInit_ex(ctx, EVP_des_ede_cfb(), NULL, key_168, iv); break;
       case 3: test =  EVP_EncryptInit_ex(ctx, EVP_des_ede_ecb(), NULL, key_168, iv); break;
       case 4: test =  EVP_EncryptInit_ex(ctx, EVP_des_ede_ofb(), NULL, key_168, iv); break;

       case 5: test =  EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key_128, iv); break;
       case 7: test =  EVP_EncryptInit_ex(ctx, EVP_aes_128_cfb(), NULL, key_128, iv); break;
       case 8: test =  EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key_128, iv); break;
       case 9: {
         test =  EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
         if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,  strlen ((char *)iv), NULL)) handleErrors();
         if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key_128,  iv))   handleErrors();
         if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, strlen ((char *)aad))) handleErrors();
         break;
       }

       case 11: test =  EVP_EncryptInit_ex(ctx, EVP_aes_128_ofb(), NULL, key_128, iv); break;
       case 12: test =  EVP_EncryptInit_ex(ctx, EVP_aes_128_xts(), NULL, key_128, iv); break;
       case 13: test =  EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key_128, iv); break;

       case 14: test =  EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key_256, iv); break;
       case 16: test =  EVP_EncryptInit_ex(ctx, EVP_aes_256_cfb(), NULL, key_256, iv); break;
       case 17: test =  EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key_256, iv); break;
       case 18: {
         test =  EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
         if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,  strlen ((char *)iv), NULL)) handleErrors();
         if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key_256,  iv))   handleErrors();
         if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, strlen ((char *)aad))) handleErrors();
         break;
       }
       case 20:  test =  EVP_EncryptInit_ex(ctx, EVP_aes_256_ofb(), NULL, key_256, iv); break;
       case 21: test =  EVP_EncryptInit_ex(ctx, EVP_aes_256_xts(), NULL, key_256, iv); break;
       case 22: test =  EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key_256, iv); break;
     }

    if(1 != test) handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *iv, unsigned char *plaintext, int parameters)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */

     int test = -10;
     switch (parameters) {
       case 1: test =  EVP_DecryptInit_ex(ctx, EVP_des_ede_cbc(), NULL, key_168, iv); break;
       case 2: test =  EVP_DecryptInit_ex(ctx, EVP_des_ede_cfb(), NULL, key_168, iv); break;
       case 3: test =  EVP_DecryptInit_ex(ctx, EVP_des_ede_ecb(), NULL, key_168, iv); break;
       case 4: test =  EVP_DecryptInit_ex(ctx, EVP_des_ede_ofb(), NULL, key_168, iv); break;

       case 5: test =  EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key_128, iv); break;
       case 7: test =  EVP_DecryptInit_ex(ctx, EVP_aes_128_cfb(), NULL, key_128, iv); break;
       case 8: test =  EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key_128, iv); break;
       case 9: {
         test =  EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
         if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, strlen ((char *)iv), NULL)) handleErrors();
         if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key_128, iv))  handleErrors();
         if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, strlen ((char *)aad))) handleErrors();
         break;
       }
       case 11: test =  EVP_DecryptInit_ex(ctx, EVP_aes_128_ofb(), NULL, key_128, iv); break;
       case 12: test =  EVP_DecryptInit_ex(ctx, EVP_aes_128_xts(), NULL, key_128, iv); break;
       case 13: test =  EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key_128, iv); break;

       case 14: test =  EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key_256, iv); break;
       case 16: test =  EVP_DecryptInit_ex(ctx, EVP_aes_256_cfb(), NULL, key_256, iv); break;
       case 17: test =  EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key_256, iv); break;
       case 18: {
         test =  EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
         if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, strlen ((char *)iv), NULL)) handleErrors();
         if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key_256, iv))  handleErrors();
         if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, strlen ((char *)aad))) handleErrors();
         break;
       }
       case 20: test =  EVP_DecryptInit_ex(ctx, EVP_aes_256_ofb(), NULL, key_256, iv); break;
       case 21: test =  EVP_DecryptInit_ex(ctx, EVP_aes_256_xts(), NULL, key_256, iv); break;
       case 22: test =  EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key_256, iv); break;
     }
    if(1 != test) handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(parameters != 18 && parameters != 9 && 1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))  handleErrors();
    if((parameters == 18 || parameters == 9) && EVP_DecryptFinal_ex(ctx, plaintext + len, &len) < 0)  handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}


int main (int argc, char *argv[])
{

  //  Parameters :
  // 1nd : 3DES/ AES (algorithm)
  // 2nd : Mode (CBC, CMC, EBC, )
  // 3th : 168 (3DES), 128 and 256 (AES) (Key size, optionnal if 3DES)

    /*
     * Set up the key and iv. Do I need to say to not hard code these in a
     * real application? :-)
     */
     if(argc < 3 || argc > 4){
        printf("Error in the parameters. Please refer to ReadMe\n");
        exit(EXIT_SUCCESS);
     }
     int parameters = -1;
     if(strcmp(argv[1],"DES") == 0 && strcmp(argv[2],"CBC") == 0 ) parameters = 1;
     else if(strcmp(argv[1],"DES") == 0 && strcmp(argv[2],"CFB") == 0 ) parameters = 2;
     else if(strcmp(argv[1],"DES") == 0 && strcmp(argv[2],"ECB") == 0 ) parameters = 3;
     else if(strcmp(argv[1],"DES") == 0 && strcmp(argv[2],"OFB") == 0 ) parameters = 4;

     else if(strcmp(argv[1],"AES") == 0 && strcmp(argv[2],"CBC") == 0 && strcmp(argv[3],"128") == 0 ) parameters = 5;
     else if(strcmp(argv[1],"AES") == 0 && strcmp(argv[2],"CCM") == 0 && strcmp(argv[3],"128") == 0 ) parameters = 6;
     else if(strcmp(argv[1],"AES") == 0 && strcmp(argv[2],"CFB") == 0 && strcmp(argv[3],"128") == 0 ) parameters = 7;
     else if(strcmp(argv[1],"AES") == 0 && strcmp(argv[2],"CTR") == 0 && strcmp(argv[3],"128") == 0 ) parameters = 8;
     else if(strcmp(argv[1],"AES") == 0 && strcmp(argv[2],"GCM") == 0 && strcmp(argv[3],"128") == 0 ) parameters = 9;
     else if(strcmp(argv[1],"AES") == 0 && strcmp(argv[2],"OFB") == 0 && strcmp(argv[3],"128") == 0 ) parameters = 11;
     else if(strcmp(argv[1],"AES") == 0 && strcmp(argv[2],"XTS") == 0 && strcmp(argv[3],"128") == 0 ) parameters = 12;
     else if(strcmp(argv[1],"AES") == 0 && strcmp(argv[2],"ECB") == 0 && strcmp(argv[3],"128") == 0 ) parameters = 13;
     else if(strcmp(argv[1],"AES") == 0 && strcmp(argv[2],"CBC") == 0 && strcmp(argv[3],"256") == 0 ) parameters = 14;
     else if(strcmp(argv[1],"AES") == 0 && strcmp(argv[2],"CCM") == 0 && strcmp(argv[3],"256") == 0 ) parameters = 15;
     else if(strcmp(argv[1],"AES") == 0 && strcmp(argv[2],"CFB") == 0 && strcmp(argv[3],"256") == 0 ) parameters = 16;
     else if(strcmp(argv[1],"AES") == 0 && strcmp(argv[2],"CTR") == 0 && strcmp(argv[3],"256") == 0 ) parameters = 17;
     else if(strcmp(argv[1],"AES") == 0 && strcmp(argv[2],"GCM") == 0 && strcmp(argv[3],"256") == 0 ) parameters = 18;
     else if(strcmp(argv[1],"AES") == 0 && strcmp(argv[2],"OFB") == 0  && strcmp(argv[3],"256") == 0 ) parameters = 20;
     else if(strcmp(argv[1],"AES") == 0 && strcmp(argv[2],"XTS") == 0  && strcmp(argv[3],"256") == 0 ) parameters = 21;
     else if(strcmp(argv[1],"AES") == 0 && strcmp(argv[2],"ECB") == 0  && strcmp(argv[3],"256") == 0 ) parameters = 22;
     else {
       printf("Parameters Error. Please refer to ReadMe.\n");
       exit(EXIT_SUCCESS);
     }
    printf("%d", parameters);
    clock_t debut, fin ;

    char chaine[TAILLE_MAX] = "";

    const char* fileName = "Whales";
    const char* openingMode = "r";
    FILE* file = fopen(fileName, openingMode);


    char plaintext[1000000] = "";
    if (file != NULL)
   {
     while (fgets(chaine, TAILLE_MAX, file) != NULL)
       {
          strcat(plaintext, chaine);
       }

   } else {
     printf("Problem while opening file");
   }
   fclose(file);

   unsigned char ciphertext[1000000];
   unsigned char decryptedtext[1000000];

   if(parameters == 6 || parameters == 15){
     int i;
     debut = clock();
     for(i = 0; i < 100000 ; i++){
               EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
               EVP_CIPHER_CTX_init(ctx);
               // Initialize the context with the alg only
              if(parameters == 6) EVP_EncryptInit(ctx, EVP_aes_128_ccm(), 0, 0);
              if(parameters == 15) EVP_EncryptInit(ctx, EVP_aes_256_ccm(), 0, 0);

               // Finaly set the key and the nonce
               if(parameters == 6) EVP_EncryptInit(ctx, 0, key_128, iv_7);
               if(parameters == 15) EVP_EncryptInit(ctx, 0, key_256, iv_7);
               // Tell the alg we will encrypt Psize bytes
               int outl = 0;
               EVP_EncryptUpdate(ctx, 0, &outl, 0, strlen ((char *)plaintext));

               EVP_EncryptUpdate(ctx, ciphertext, &outl, plaintext, strlen ((char *)plaintext));
               // I am not sure this is necessary
               EVP_EncryptFinal(ctx, &ciphertext[outl], &outl);
               // Append the tag to the end of the encrypted output
               EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, 12, &ciphertext[strlen ((char *)plaintext)]);
     }
     fin = clock();
     float time_for_many = ((float)fin-debut)/CLOCKS_PER_SEC;
     printf("Encryption time is %.10f seconds for 100000 runs.\n", time_for_many);
     printf("Encryption time is %.10f seconds for 1 runs.\n", time_for_many/100000);
     /* Do something useful with the ciphertext here */
     printf("Ciphertext is:\n");
     BIO_dump_fp (stdout, (const char *)ciphertext, strlen ((char *)ciphertext));

     //Decription
     debut = clock();
     for(i = 0; i < 100000 ; i++){
               EVP_CIPHER_CTX* ctx2 = EVP_CIPHER_CTX_new();
               EVP_CIPHER_CTX_init(ctx2);
               // Just set the alg
               if(parameters == 6) EVP_DecryptInit(ctx2, EVP_aes_128_ccm(), 0, 0);
               if(parameters == 15) EVP_DecryptInit(ctx2, EVP_aes_256_ccm(), 0, 0);

                EVP_CIPHER_CTX_ctrl(ctx2, EVP_CTRL_CCM_SET_IVLEN, 7, 0);
               // Set the tag from the end of the encrypted array
               EVP_CIPHER_CTX_ctrl(ctx2, EVP_CTRL_CCM_SET_TAG, 12, ciphertext + strlen ((char *)plaintext));
               // Set key and nonce
               if(parameters == 6) EVP_DecryptInit(ctx2, 0, key_128, iv_7);
               if(parameters == 15) EVP_DecryptInit(ctx2, 0, key_256, iv_7);
               int out2 = 0;
               // We will encrypt Psize bytes
               EVP_DecryptUpdate(ctx2, 0, &out2, 0, strlen ((char *)plaintext));
               // Add AAD for verification
               //  EVP_DecryptUpdate(ctx2, 0, &outl, A, Asize);
               // Time to decrypt the data into D
               EVP_DecryptUpdate(ctx2, decryptedtext, &out2, ciphertext, strlen ((char *)plaintext));
               // Not sure if this is needed
               EVP_DecryptFinal(ctx2, &decryptedtext[out2], &out2);
      }
      fin = clock();
      time_for_many = ((float)fin-debut)/CLOCKS_PER_SEC;
      printf("Decryption time is %.10f seconds for 100000 runs.\n", time_for_many);
      printf("Decryption time is %.10f seconds for 1 runs.\n", time_for_many/100000);
      printf("Plaintext is:\n");
      printf("%s\n", decryptedtext);

       }else {

    /*
     * Buffer for ciphertext. Ensure the buffer is long enough for the
     * ciphertext which may be longer than the plaintext, depending on the
     * algorithm and mode.
     */

    int decryptedtext_len, ciphertext_len;
    debut = clock();
    /* Encrypt the plaintext */
    int i = 0;
    for(i = 0; i < 100; i++){
      ciphertext_len = encrypt (plaintext, strlen ((char *)plaintext), iv, ciphertext, parameters);
    }
    fin = clock();
    float time_for_many = ((float)fin-debut)/CLOCKS_PER_SEC;
    printf("Encryption time is %.10f seconds for 100 runs.\n", time_for_many);
    printf("Encryption time is %.10f seconds for 1 runs.\n", time_for_many/100);

    /* Do something useful with the ciphertext here */
    printf("Ciphertext is:\n");
   BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

   debut = clock();
    /* Decrypt the ciphertext */
    for(i = 0; i < 100; i++){
      decryptedtext_len = decrypt(ciphertext, ciphertext_len, iv, decryptedtext, parameters);
    }
    fin = clock();
    time_for_many = ((float)fin-debut)/CLOCKS_PER_SEC;
    printf("Decryption time is %.10f seconds for 100 runs.\n", time_for_many);
    printf("Decryption time is %.10f seconds for 1 runs.\n", time_for_many/100);    /* Add a NULL terminator. We are expecting printable text */
    decryptedtext[decryptedtext_len] = '\0';

    /* Show the decrypted text */
    printf("Decrypted text is:\n");
    printf("%s\n", decryptedtext);

}
    return 0;
}
