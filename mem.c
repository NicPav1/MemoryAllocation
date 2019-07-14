////////////////////////////////////////////////////////////////////////////////
// Main File:        mem.c
// This File:        mem.c
// Other Files:      mem.h
// Semester:         CS 354 Spring 2019
//
// Author:           Nicolas Pavlakovic
// Email:            pavlakovic@wisc.edu
// CS Login:         pavlakovic
//
/////////////////////////// OTHER SOURCES OF HELP //////////////////////////////
//                   fully acknowledge and credit all sources of help,
//                   other than Instructors and TAs.
//
// Persons:          Identify persons by name, relationship to you, and email.
//                   Describe in detail the the ideas and help they provided.
//
// Online sources:   avoid web searches to solve your problems, but if you do
//                   search, be sure to include Web URLs and description of 
//                   of any information you find.
//////////////////////////// 80 columns wide ///////////////////////////////////
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include "mem.h"
#include <limits.h>

/*
 * This structure serves as the header for each allocated and free block.
 * It also serves as the footer for each free block but only containing size.
 */
typedef struct block_header {
        int size_status;
    /*
    * Size of the block is always a multiple of 8.
    * Size is stored in all block headers and free block footers.
    *
    * Status is stored only in headers using the two least significant bits.
    *   Bit0 => least significant bit, last bit
    *   Bit0 == 0 => free block
    *   Bit0 == 1 => allocated block
    *
    *   Bit1 => second last bit 
    *   Bit1 == 0 => previous block is free
    *   Bit1 == 1 => previous block is allocated
    * 
    * End Mark: 
    *  The end of the available memory is indicated using a size_status of 1.
    * 
    * Examples:
    * 
    * 1. Allocated block of size 24 bytes:
    *    Header:
    *      If the previous block is allocated, size_status should be 27
    *      If the previous block is free, size_status should be 25
    * 
    * 2. Free block of size 24 bytes:
    *    Header:
    *      If the previous block is allocated, size_status should be 26
    *      If the previous block is free, size_status should be 24
    *    Footer:
    *      size_status should be 24
    */
} block_header;         

/* Global variable - DO NOT CHANGE. It should always point to the first block,
 * i.e., the block at the lowest address.
 */

block_header *start_block = NULL;

/* 
 * Function for allocating 'size' bytes of heap memory.
 * Argument size: requested size for the payload
 * Returns address of allocated block on success.
 * Returns NULL on failure.
 * This function should:
 * - Check size - Return NULL if not positive or if larger than heap space.
 * - Determine block size rounding up to a multiple of 8 and possibly adding padding as a result.
 * - Use BEST-FIT PLACEMENT POLICY to find the block closest to the required block size
 * - Use SPLITTING to divide the chosen free block into two if it is too large.
 * - Update header(s) and footer as needed.
 * Tips: Be careful with pointer arithmetic.
 */
void* Alloc_Mem(int size) {
    // Your code goes in here.
	if(size < 1){
		return NULL;
	}
	int blockSize = size +sizeof(block_header);
	while((blockSize % 8) != 0){
    blockSize += 1;
  }
  //Pointer to keep track of current block
	block_header *curr_block = start_block;
  //Pointer to keep track of best fit block for placing
  block_header *best_block = NULL;
  //Keeps track of the best block size
  int best_size = INT_MAX;
  //ap bits for the current block 
  int ap_bits_current = 0;
  
  //status of the best block
  int ap_bits_best = 0;
  
  //0 = not allocated, 1 = allocated
  int allocated = 0;
  //While we aren't at the last block 
  while(curr_block->size_status != 1){
    ap_bits_current = curr_block->size_status;
    //Gets the actual size of the block minus the a/p bits
    while((ap_bits_current)%8 != 0){
      ap_bits_current--;
    }
    //Gets the a and the p bits from the current block
    ap_bits_current = (curr_block->size_status) - ap_bits_current;
    //Checks if the current block is a better fit than the current best
    if(curr_block->size_status <= best_size){
      //Checking if the current block is free && the current block is large
      //enough to fit the placed block
      if((curr_block->size_status % 2 == 0) && (curr_block->size_status -
        ap_bits_current >= blockSize)){
        allocated = 1;
        best_block = curr_block;
        ap_bits_best = ap_bits_current;
        best_size = best_block->size_status;
      }
    }
    //Gets the address for the next block in the heap
    curr_block = (block_header*)((char*)curr_block + curr_block->size_status -
    ap_bits_current);
  }
  //No best block was found so return NULL
  if(allocated == 0){
    return NULL;
  }    

  int unused = best_block->size_status - blockSize - ap_bits_best;
  //If a best block was found, update its status
  best_block->size_status = blockSize + ap_bits_best + 1;
  
  //Code to split the block if it's too large 
  if(unused != 0){
    //Creates a new block header for the new block
    block_header *new_block = (block_header*)((char*)best_block + blockSize);
    new_block->size_status = unused + 2;

    //Sets the new footer for the new block
    block_header *new_footer = (block_header*)((char*)new_block +
    (new_block->size_status & 0xFFFC) - 4);
    new_footer->size_status = unused;
  }
  //Creates the pointer to return the address
  char* address =  (char*)best_block - 4;
  if(address != NULL){
    return address;
  }
  return NULL;
}

/* 
 * Function for freeing up a previously allocated block.
 * Argument ptr: address of the block to be freed up.
 * Returns 0 on success.
 * Returns -1 on failure.
 * This function should:
 * - Return -1 if ptr is NULL.
 * - Return -1 if ptr is not a multiple of 8.
 * - Return -1 if ptr is outside of the heap space.
 * - Return -1 if ptr block is already freed.
 * - USE IMMEDIATE COALESCING if one or both of the adjacent neighbors are free.
 * - Update header(s) and footer as needed.
 */                    
int Free_Mem(void *ptr) {         
    // Your code goes in here.
    //Returns -1 if ptr is NULL
    if(ptr == NULL){
      return -1;
    }
    if((int)ptr%8 != 0){
      return -1;
    }
  
    //Check if the ptr is before the Heap space
    block_header* iterator = start_block;
    if((unsigned int)ptr < (unsigned int)((char*)start_block - 4)){
      printf("%p %p", (void*)ptr, (void*)start_block);
      return -1;
    }
    
    //Check if the ptr is after the Heap space
    while(iterator->size_status != 1){
      iterator = (block_header*)((char*)iterator + 8);
    }
    if((int)ptr > (int)iterator){
      return -1;
    }
    

    //Makes a block header pointing at the address of the ptr 
    block_header* freed_block = (block_header*)((char*)ptr + 4);
    //Returns -1 if the block is already freed
    if((freed_block->size_status%2) == 0){
      return -1;
    }
    //Updates the freed block's header to 'free'
    freed_block->size_status -= 1; 
    
    int size_of_freed = freed_block->size_status;
    
    //Gets the ap bits for the freed block 
    int freed_ap_bit = 0;
    if(size_of_freed % 4 != 0){ //If prev. block is alloc.
      freed_ap_bit += 2;
    } 
    
    //Header pointer to the next block 
    block_header* next = (block_header*)((char*)freed_block +
      freed_block->size_status - freed_ap_bit);
    
    if(next->size_status != 1){ //If next block isn't end
      //Subtract 2 from next header because prev. is now free
      next->size_status = next->size_status - 2;
      //If the next block is free
      if(next->size_status % 2 == 0){
        //Coalesce the two blocks together.
        freed_block->size_status = freed_block->size_status + next->size_status;
      }
    }

    //Need to check previous block to see if it must be coalesced
    //Creates a pointer to the first block to use to iterate
    block_header* current_block = start_block;
    
    if(freed_block != start_block){
      //Finding the block right before the freed block
      while((block_header*)((char*)current_block + (current_block->size_status &
        0xFFFC)) != freed_block){
        current_block = (block_header*)((char*)current_block +
          (current_block->size_status & 0xFFFC));  
      } 
    }

    //Temporary block to hold the freed block while coalescing
    block_header* temp_block = freed_block;

    //If the previous block is free
    if(freed_block->size_status % 4 == 0){
      freed_block = current_block;
      //Coalescing the two free blocks
      freed_block->size_status = temp_block->size_status +
        freed_block->size_status;

      //Get the ap bits for the free block
      size_of_freed = freed_block->size_status;
      freed_ap_bit = 0;
      if(size_of_freed % 4 != 0){
        freed_ap_bit += 2;
      }

      //Updates the footer of the current free block
      ((block_header*)((char*)freed_block+freed_block->size_status-freed_ap_bit-4))->size_status
        = freed_block->size_status - freed_ap_bit;
    } 

    return 0;
}

/*
 * Function used to initialize the memory allocator.
 * Intended to be called ONLY once by a program.
 * Argument sizeOfRegion: the size of the heap space to be allocated.
 * Returns 0 on success.
 * Returns -1 on failure.
 */                    
int Init_Mem(int sizeOfRegion) {         
    int pagesize;
    int padsize;
    int fd;
    int alloc_size;
    void* space_ptr;
    block_header* end_mark;
    static int allocated_once = 0;
  
    if (0 != allocated_once) {
        fprintf(stderr, 
        "Error:mem.c: Init_Mem has allocated space during a previous call\n");
        return -1;
    }
    if (sizeOfRegion <= 0) {
        fprintf(stderr, "Error:mem.c: Requested block size is not positive\n");
        return -1;
    }

    // Get the pagesize
    pagesize = getpagesize();

    // Calculate padsize as the padding required to round up sizeOfRegion 
    // to a multiple of pagesize
    padsize = sizeOfRegion % pagesize;
    padsize = (pagesize - padsize) % pagesize;

    alloc_size = sizeOfRegion + padsize;

    // Using mmap to allocate memory
    fd = open("/dev/zero", O_RDWR);
    if (-1 == fd) {
        fprintf(stderr, "Error:mem.c: Cannot open /dev/zero\n");
        return -1;
    }
    space_ptr = mmap(NULL, alloc_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, 
                    fd, 0);
    if (MAP_FAILED == space_ptr) {
        fprintf(stderr, "Error:mem.c: mmap cannot allocate space\n");
        allocated_once = 0;
        return -1;
    }
  
    allocated_once = 1;

    // for double word alignment and end mark
    alloc_size -= 8;

    // To begin with there is only one big free block
    // initialize heap so that start block meets 
    // double word alignement requirement
    start_block = (block_header*) space_ptr + 1;
    end_mark = (block_header*)((void*)start_block + alloc_size);
  
    // Setting up the header
    start_block->size_status = alloc_size;

    // Marking the previous block as used
    start_block->size_status += 2;

    // Setting up the end mark and marking it as used
    end_mark->size_status = 1;

    // Setting up the footer
    block_header *footer = (block_header*) ((char*)start_block + alloc_size - 4);
    footer->size_status = alloc_size;
  
    return 0;
}         
                 
/* 
 * Function to be used for DEBUGGING to help you visualize your heap structure.
 * Prints out a list of all the blocks including this information:
 * No.      : serial number of the block 
 * Status   : free/used (allocated)
 * Prev     : status of previous block free/used (allocated)
 * t_Begin  : address of the first byte in the block (where the header starts) 
 * t_End    : address of the last byte in the block 
 * t_Size   : size of the block as stored in the block header
 */                     
void Dump_Mem() {         
    int counter;
    char status[5];
    char p_status[5];
    char *t_begin = NULL;
    char *t_end = NULL;
    int t_size;

    block_header *current = start_block;
    counter = 1;

    int used_size = 0;
    int free_size = 0;
    int is_used = -1;

    fprintf(stdout, "************************************Block list***\
                    ********************************\n");
    fprintf(stdout, "No.\tStatus\tPrev\tt_Begin\t\tt_End\t\tt_Size\n");
    fprintf(stdout, "-------------------------------------------------\
                    --------------------------------\n");
  
    while (current->size_status != 1) {
        t_begin = (char*)current;
        t_size = current->size_status;
    
        if (t_size & 1) {
            // LSB = 1 => used block
            strcpy(status, "used");
            is_used = 1;
            t_size = t_size - 1;
        } else {
            strcpy(status, "Free");
            is_used = 0;
        }

        if (t_size & 2) {
            strcpy(p_status, "used");
            t_size = t_size - 2;
        } else {
            strcpy(p_status, "Free");
        }

        if (is_used) 
            used_size += t_size;
        else 
            free_size += t_size;

        t_end = t_begin + t_size - 1;
    
        fprintf(stdout, "%d\t%s\t%s\t0x%08lx\t0x%08lx\t%d\n", counter, status, 
        p_status, (unsigned long int)t_begin, (unsigned long int)t_end, t_size);
    
        current = (block_header*)((char*)current + t_size);
        counter = counter + 1;
    }

    fprintf(stdout, "---------------------------------------------------\
                    ------------------------------\n");
    fprintf(stdout, "***************************************************\
                    ******************************\n");
    fprintf(stdout, "Total used size = %d\n", used_size);
    fprintf(stdout, "Total free size = %d\n", free_size);
    fprintf(stdout, "Total size = %d\n", used_size + free_size);
    fprintf(stdout, "***************************************************\
                    ******************************\n");
    fflush(stdout);

    return;
}         
