#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/syscall.h"


void free_children(struct list *child_list);
static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
static void get_stack_args(char *file_name, void **esp, char **save_ptr);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name)
{
    char *fn_copy;
    char *save_ptr;
    char *name;
    tid_t tid;



    name = malloc(strlen(file_name)+1);
    strlcpy (name, file_name, strlen(file_name)+1);
    name = strtok_r (name," ",&save_ptr);

    /* Make a copy of FILE_NAME.
        Otherwise there's a race between the caller and load(). */
    fn_copy = palloc_get_page (0);
    if (fn_copy == NULL)
        return TID_ERROR;
    strlcpy (fn_copy, file_name, PGSIZE);

    /* Create a new thread to execute FILE_NAME. */
    tid = thread_create (name, PRI_DEFAULT, start_process, fn_copy);
    free(name);
    if (tid == TID_ERROR)
    {
        palloc_free_page (fn_copy);
    }
    return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
    char *file_name = file_name_;
    struct intr_frame if_;
    bool success;

    /* Initialize interrupt frame and load executable. */
    memset (&if_, 0, sizeof if_);
    if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
    if_.cs = SEL_UCSEG;
    if_.eflags = FLAG_IF | FLAG_MBS;
    success = load (file_name, &if_.eip, &if_.esp);

    // if this thread have a parent
    if(thread_current()->parent != NULL)
    {
        // get this thread as a child
        struct child_element *child = get_child(thread_current() -> tid, &thread_current()->parent->child_list);
        // setting the load status
        child ->loaded_success = success;
    }
    // wake up my parent which wait me to load successfully
    sema_up(&thread_current() -> sema_exec);

    //free file name
    palloc_free_page(file_name);
    if (!success)
    {
        thread_exit();
    }
    /* Start the user process by simulating a return from an
    interrupt, implemented by intr_exit (in
    threads/intr-stubs.S).  Because intr_exit takes all of its
    arguments on the stack in the form of a `struct intr_frame',
    we just point the stack pointer (%esp) to our stack frame
    and jump to it. */
    asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
    NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t tid)
{
    //get my child which have this tid
    struct child_element *child = get_child(tid, &thread_current()-> child_list);
    // check if this is the 1st call of child
    if(child -> first_time)
    {
        //mark that child was called before
        child -> first_time = false;
        //check if this child is still alive
        if(child -> cur_status == STILL_ALIVE)
        {
            // make the current thread wait this child
            sema_down(&(child -> real_child -> sema_wait));
        }
        //after wake up, return the exit status
        return child-> exit_status;
    }
    return -1;
}

/* Free the current process's resources. */
void
process_exit (void)
{
    struct thread *cur = thread_current();
    uint32_t *pd;

    // if this thread have a parent
    if(thread_current()->parent != NULL)
    {
        // get this thread as a child
        struct child_element *child = get_child(thread_current() -> tid, &thread_current()->parent->child_list);
        // if this thread is still alive
        if(child -> cur_status == STILL_ALIVE)
        {
            // this thread had been killed
            child -> cur_status = WAS_KILLED;
            child -> exit_status = -1;
        }
    }

    // wake up my parent which wait my lock
    sema_up(&thread_current()->sema_wait);

    //Free my Children
    free_children(&thread_current()->child_list);

    // lose my parent
    thread_current()->parent = NULL;

    // allow other threads to use my executable file
    if (cur -> exec_file != NULL)
    {
        file_allow_write(cur -> exec_file);
    }

    // close my executable file
    file_close(cur->exec_file);

    //close all file the current thread have
    close_all(&cur->fd_list);

    /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
    pd = cur->pagedir;
    if (pd != NULL)
    {
        /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
        cur->pagedir = NULL;
        pagedir_activate(NULL);
        pagedir_destroy(pd);
    }
}

/**
free all the children in the child_list
*/
void
free_children(struct list *child_list)
{
    struct list_elem* e1 = list_begin(child_list);
    while(e1!=list_end(child_list))
    {
        struct list_elem* next = list_next(e1);
        struct child_element* c = list_entry(e1, struct child_element, child_elem);
        list_remove(e1);
        free(c);
        e1 = next;
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
    struct thread *t = thread_current ();

    /* Activate thread's page tables. */
    pagedir_activate (t->pagedir);

    /* Set thread's kernel stack for use in processing
       interrupts. */
    tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
{
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
{
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) //eip point to function to go after load program
// esp point to address
{
// printf ("hello from load\n");
    struct thread *t = thread_current ();
    struct Elf32_Ehdr ehdr; //save header info of ELF file
    struct file *file = NULL; 
    off_t file_ofs; //hold the current offset in file (place that already read currently)
    bool success = false; //success or failed in load a program
    int i; // use in loop
    /*stack arguments*/
    char *fn_copy; //file name copy
    char *save_ptr;

    /* Allocate and activate page directory. */
    t->pagedir = pagedir_create (); //new page space for current thread and save the address in t->...
   // this is for saving the claims of pointers of the page
    if (t->pagedir == NULL) //check that making a new page is successfull or not
        goto done; //stop uploading and go to done label
    process_activate (); //call functions to active page of current thread
//necessary because current thread may prevent loading of new pages after switching.

    int name_length = strlen (file_name)+1; //size of file name string + 1 bit for end of string
    fn_copy = malloc (name_length);//set memory for copy file name as large as size and first address at fncopy 
    strlcpy(fn_copy, file_name, name_length); //copy and strlcpy is safer than strcpy cause it aint go memory limit
    fn_copy = strtok_r (fn_copy, " ", &save_ptr); //use strtok_r for tokenise by " "
   //The pointer is stored in `save_ptr` where it points after all the words that have been separated so far.

    file = filesys_open (fn_copy);//open file and store file address in "file"
//If successful, a file handle is opened as the file opener for the current process.
    if (file == NULL) //if not success and failed to open
    {
        printf ("load: %s: open failed\n", file_name);
        goto done; //stop running
    }

    /* Read and verify executable header. */
    if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
   //Executable header information (ELF) is read from the read file and validity checked by conditional expressions
   //If any ofconditions failed,"error loading executable" print with file name and end running:
            || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
            || ehdr.e_type != 2
            || ehdr.e_machine != 3 //The expected target machine is not (Intel 80386)
            || ehdr.e_version != 1 //The ELF type of the file is not the expected type (ELF32)
            || ehdr.e_phentsize != sizeof (struct Elf32_Phdr) //The expected target machine is not (Intel 80386)
            || ehdr.e_phnum > 1024) //The number of entries in the section should not exceed the limit (1024).
    {
        printf ("load: %s: error loading executable\n", file_name);
        goto done;
    }

    /* Read program headers. */
    file_ofs = ehdr.e_phoff;
//offset to read the program header in `file` is extracted from the ELF file header and stored in `file_ofs`.
    for (i = 0; i < ehdr.e_phnum; i++)
    {//loop starts to traverse all parts of program in ELF header.number of items in section is equal to `ehdr.e_phnum`.
        struct Elf32_Phdr phdr;
//new instance of `struct Elf32_Phdr` is defined to store each part of the program.
        if (file_ofs < 0 || file_ofs > file_length (file))
            goto done;
       //If current offset is outside the allowed range,loading operation ends and goes to the `done` label.
        file_seek (file, file_ofs);
//The read position of the file is set to the current offset.
        if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
            goto done;
//infoof each part is read from the file,
//if the return value of the `file_read` function is not equal to the expectation,loading ends and goto `done' tag.
        file_ofs += sizeof phdr;
//The offset is updated to point to the next part of the program header.
        switch (phdr.p_type)
        { //A `switch casse` flow control structure is started to check the type of each part of the program.
        case PT_NULL: //This section is ignored if section type does not need to be loaded or is unknown.
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
            /* Ignore this segment. */
            break;
        case PT_DYNAMIC: //If the section is of a type that is not desired, loading  ends and goes to the `done` label.
        case PT_INTERP:
        case PT_SHLIB:
            goto done;
        case PT_LOAD:
   //If the segment is a loadable segment and its information is valid, its loading operation will begin.
            if (validate_segment (&phdr, file))
            {
                bool writable = (phdr.p_flags & PF_W) != 0;
               //Determines whether the section is writable or not based on `PF_W` flag.
                uint32_t file_page = phdr.p_offset & ~PGMASK;
               //The offset in the file is calculated.
                uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
               //Calculate offset in memory.
                uint32_t page_offset = phdr.p_vaddr & PGMASK;
               //The offset is calculated to move the content of the section from memory.
                uint32_t read_bytes, zero_bytes;
               //Variables are defined to store the number of bytes to be read from the file 
               //and the number of zero bytes.
                if (phdr.p_filesz > 0)
                { //If the file size of the section is greater than zero, 
                   //the section is normal and should be read from the file.
                    /* Normal segment.
                       Read initial part from disk and zero the rest. */
                    read_bytes = page_offset + phdr.p_filesz;
                   //The number of readable bytes is calculated.
                    zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                  - read_bytes);
                }//The number of zero bytes is calculated.
                else
                {
                   //Otherwise, the section is completely zero and no need to read from the file.
                    /* Entirely zero.
                       Don't read anything from disk. */
                    read_bytes = 0; //The number of readable bytes is zero.
                    zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
               //The number of bytes to be zeroed is equal to the size of the section in memory
               // and is calculated as much as necessary to fill the pages.
                if (!load_segment (file, file_page, (void *) mem_page,
                                   read_bytes, zero_bytes, writable))
                    goto done;
//`load_segment` function is called to load the desired section of the file, 
   //if the operation is not successful, the loading operation ends and goes to the `done'
            }
            else
                goto done;
            break;
        }
    } //end of for loop

    /* Set up stack. */
    if (!setup_stack (esp))
        goto done;
    get_stack_args (fn_copy, esp, &save_ptr);
    //palloc_free_page (fn_copy);
    free(fn_copy);

    /* Start address. */
    *eip = (void (*) (void)) ehdr.e_entry;
//The program execution start address is stored as the entry point.
    success = true;
//Indicates that the upload operation was successful.
done:
    /* We arrive here whether the load is successful or not. */
    if (success)
    {
        /*deny*/
        file_deny_write(file);
   //Write access to the program file is blocked to prevent unauthorized(not allow) changes.
        thread_current() -> exec_file = file;
    }//The file we are executing is specified as the current executable file.
    else file_close (file);
    return success;
}
/*get stack arguments*/
static
//With these lines, the load() function is complete.
//This function is responsible for loading an ELF executable from a file.
//open a file - check the ELF header to make sure the file format is correct - 
//Then the program is loaded along with all the sections and programs.
//data is loaded into these pages - Finally, a stack is created for the program 
//and the starting address of the program is specified as the entry point for the CPU.
void get_stack_args(char *file_name, void **esp, char **save_ptr)
{
//parameters: `file_name` for the name of the program file,
//`esp` for the starting address of the stack, 
//`save_ptr` for the pointer used for the next use of the `strtok_r` function.
    char *token = file_name;
   //Creating a pointer variable to the string named `token` and setting it to `file_name`.
    void *stack_pointer = *esp;
   //Creating a void pointer variable named `stack_pointer` 
   //and setting it to the value of the address that `esp` points to.
    int argc = 0;
   //Creating an integer variable called `argc' and setting it to zero.
   //This variable is used to count the number of command line arguments.
    int total_length = 0; //This variable is used to calculate the total length of the argument strings.
    /*split and insert in the stack
     * /bin/ls -l foo bar
     * /bin/ls
     * -l
     * foo
     * bar*/
    while (token != NULL)
    {
       //Start a loop that continues until `token' points to a valid substring.
        int arg_length = (strlen(token) + 1);
       //Calculate the length of the current substring +1 to add a final character (NULL).
        total_length += arg_length;
       //Add the length of the current substring to `total_length`.
        stack_pointer -= arg_length;
       //Move the stack pointer up to insert the new subthread.
        memcpy(stack_pointer, token, arg_length);
       //Copy the current substring to the location pointed to by the stack pointer.
        argc++;
        token = strtok_r(NULL, " ", save_ptr);
       //Using ``strtok_r'' function to get the next substring address.
    }

    char *args_pointer = (char *) stack_pointer;
//Creating a string pointer variable called `args_pointer' 
//and setting it to the address pointed to by `stack_pointer'.
    /*adding word align*/
    int  word_align = 0;
   //This variable is used to calculate the number of additional characters for align arrangement.
    while (total_length % 4 != 0)
    { 
       //Start a loop to calculate the number of additional characters to align the stack.
        word_align++;
        total_length++;
    }
    if (word_align != 0)
    {
        stack_pointer -= word_align;
        memset(stack_pointer, 0, word_align);
    }

    /*adding null char*/
    stack_pointer -= sizeof(char *);
    memset(stack_pointer, 0, 1);

    /*adding argument address*/
    int args_pushed = 0;
    while(argc > args_pushed)
    {
        stack_pointer -= sizeof(char *);
        *((char **) stack_pointer) = args_pointer;
        args_pushed++;
        args_pointer += (strlen(args_pointer) + 1);
    }

    /*adding char** */
    char ** first_fetch = (char **) stack_pointer;
    stack_pointer -= sizeof(char **);
    *((char ***) stack_pointer) = first_fetch;

    /*adding number of arrguments*/
    stack_pointer -= sizeof(int);
    *(int *) (stack_pointer) = argc;

    /*adding return address*/
    stack_pointer -= sizeof(int*);
    *(int *) (stack_pointer) = 0;
    *esp = stack_pointer;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file)
{
    /* p_offset and p_vaddr must have the same page offset. */
    if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
        return false;

    /* p_offset must point within FILE. */
    if (phdr->p_offset > (Elf32_Off) file_length (file))
        return false;

    /* p_memsz must be at least as big as p_filesz. */
    if (phdr->p_memsz < phdr->p_filesz)
        return false;

    /* The segment must not be empty. */
    if (phdr->p_memsz == 0)
        return false;

    /* The virtual memory region must both start and end within the
       user address space range. */
    if (!is_user_vaddr ((void *) phdr->p_vaddr))
        return false;
    if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
        return false;

    /* The region cannot "wrap around" across the kernel virtual
       address space. */
    if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
        return false;

    /* Disallow mapping page 0.
       Not only is it a bad idea to map page 0, but if we allowed
       it then user code that passed a null pointer to system calls
       could quite likely panic the kernel by way of null pointer
       assertions in memcpy(), etc. */
    if (phdr->p_vaddr < PGSIZE)
        return false;

    /* It's okay. */
    return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
    ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
    ASSERT (pg_ofs (upage) == 0);
    ASSERT (ofs % PGSIZE == 0);

    file_seek (file, ofs);
    while (read_bytes > 0 || zero_bytes > 0)
    {
        /* Calculate how to fill this page.
           We will read PAGE_READ_BYTES bytes from FILE
           and zero the final PAGE_ZERO_BYTES bytes. */
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        /* Get a page of memory. */
        uint8_t *kpage = palloc_get_page (PAL_USER);
        if (kpage == NULL)
            return false;

        /* Load this page. */
        if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
            palloc_free_page (kpage);
            return false;
        }
        memset (kpage + page_read_bytes, 0, page_zero_bytes);

        /* Add the page to the process's address space. */
        if (!install_page (upage, kpage, writable))
        {
            palloc_free_page (kpage);
            return false;
        }

        /* Advance. */
        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;
        upage += PGSIZE;
    }
    return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp)
{
    uint8_t *kpage;
    bool success = false;

    kpage = palloc_get_page (PAL_USER | PAL_ZERO);
    if (kpage != NULL)
    {
        success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
        if (success)
            *esp = PHYS_BASE;
        else
            palloc_free_page (kpage);
    }
    return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
    struct thread *t = thread_current ();

    /* Verify that there's not already a page at that virtual
       address, then map our page there. */
    return (pagedir_get_page (t->pagedir, upage) == NULL
            && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
