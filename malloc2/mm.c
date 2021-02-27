/*
 * mm-naive.c - The fastest, least memory-efficient malloc package.
 * 
 * In this naive approach, a block is allocated by simply incrementing
 * the brk pointer.  A block is pure payload. There are no headers or
 * footers.  Blocks are never coalesced or reused. Realloc is
 * implemented directly using mm_malloc and mm_free.
 *
 * NOTE TO STUDENTS: Replace this header comment with your own header
 * comment that gives a high level description of your solution.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

#include "mm.h"
#include "memlib.h"

 

/*********************************************************
 * NOTE TO STUDENTS: Before you do anything else, please
 * provide your team information in the following struct.
 ********************************************************/
team_t team = {
    /* Team name */
    "ateam",
    /* First member's full name */
    "Harry Bovik",
    /* First member's email address */
    "bovik@cs.cmu.edu",
    /* Second member's full name (leave blank if none) */
    "",
    /* Second member's email address (leave blank if none) */
    ""
};

/* single word (4) or double word (8) alignment */
#define ALIGNMENT 8
#define init_size 36+62*4+63*4

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~0x7)


#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))

#define set(p,v) (*(unsigned int*)(p)=(v))
#define get(p) (*(unsigned int*)(p))

#define pack(size,if_use) ((size) | (if_use))
#define set_size(p,v) (set(p+4,v))
#define get_size(p) (get(p+4))
#define is_inuse(p) (get_size(p)&1)

#define get_f_idx(s) ((s>>3)-2)
#define get_fbin(i) (mem_start_brk+4*i)

#define get_ubin() (mem_start_brk+4*7-8)
#define get_fd(p) (*(unsigned int*)(p+8))
#define get_bk(p) (*(unsigned int*)(p+0xc))
#define set_fd(p,v) (*(unsigned int*)(p+8)=(v))
#define set_bk(p,v) (*(unsigned int*)(p+0xc)=(v))

#define if_in_small(s) (s<0x200)
#define get_s_idx(s) ((s>>3)-2)
#define get_smallbin(i) *(unsigned int*)(mem_start_brk+4*(i+9))

#define if_large(s) (s>=0x200)
#define get_fn(p) (*(unsigned int*)(p+0x10))
#define set_fn(p,v) (*(unsigned int*)(p+0x10)=(v))
#define get_bn(p) (*(unsigned int*)(p+0x14))
#define set_bn(p,v) (*(unsigned int*)(p+0x14)=(v))
#define get_next_bin(p) (p+8)

/* 
 * mm_init - initialize the malloc package.
 */
static char *mem_start_brk;
static char *mem_head_end;
static char *mem_max_addr;
static char *top_chunk;
static int f_con=0;
static int row=0;

int static fastbin_not_empty()
{
	int i,sign=0;
	void *bin;
	for(i=0;i<7 && !sign;i++)
	{
		bin=get_fbin(i);
		if(get(bin)!=0)
		sign=1;
	}
	return sign;
}

void static fastbin_consolidate()
{
	int i;
	void *victim,*temp;
	f_con=1;
	for(i=0;i<7;i++)
	{
		victim=get(get_fbin(i));
		for(;victim;)
		{
			temp=get_fd(victim);
			mm_free(victim+8);
			victim=temp;
		}
		set(get_fbin(i),0);
	}
	f_con=0;
}

void static my_unlink(void *ptr)
{
	void *fwd,*bck;
	fwd=get_fd(ptr);
	bck=get_bk(ptr);
	if(get_fd(bck)!=ptr || get_bk(fwd)!=ptr)
	{
		perror("corrupted double linked bin\n");
		exit(0);
	}
	set_fd(bck,fwd);
	set_bk(fwd,bck);
}

void* get_largebin(int size)
{
	int idx;
	if(size<0x200)
	idx=0;
	else if(size<0x600)
	idx=(size-0x200)>>5;
	else if(size<0x1600)
	idx=((size-0x600)>>8)+32;
	else if(size<0x5600)
	idx=((size-0x1600)>>11)+48;
	else if(size<0x15600)
	idx=((size-0x5600)>>14)+56;
	else if(size<0x55600)
	idx=((size-0x15600)>>17)+60;
	else
	idx=62;
	return get(mem_start_brk+4*(71+idx));
}

int mm_init(void)
{
	int i;
	void *small_bin,*large_bin;
	mem_init();
	mem_start_brk=mem_heap_lo();
	mem_sbrk(init_size);
	for(i=0;i<7;i++)
	set(mem_start_brk+4*i,0);//fastbin 0x10-0x40
	set(mem_start_brk+4*7,mem_start_brk+4*7-8);//unsorted bin fd
	set(mem_start_brk+4*8,mem_start_brk+4*7-8);//unsorted bin bk
	for(i=0;i<62;i++)//small bin 0x10-0x1f8
	{
		small_bin=mem_sbrk(8);
		set(mem_start_brk+4*(9+i),small_bin-8);
		set(small_bin,small_bin-8);
		set(small_bin+4,small_bin-8);
	}
	for(i=0;i<63;i++)//large bin 0x200-0x5e0 0x600-0x1500 0x1600-0x4e00 0x5600-0xd600 0x15600-0x21600  0x55600-unlimited
	{
		large_bin=mem_sbrk(8);
		set(mem_start_brk+4*(71+i),large_bin-8);
		set(large_bin,large_bin-8);
		set(large_bin+4,large_bin-8);
	}
	mem_head_end=mem_start_brk+init_size+8*62+8*63-8;
	mem_max_addr=mem_head_end+8;
	top_chunk=mem_max_addr;
    return 0;
}

/* 
 * mm_malloc - Allocate a block by incrementing the brk pointer.
 *     Always allocate a block whose size is a multiple of the alignment.
 */
void *mm_malloc(size_t size)
{
    int newsize = ALIGN(size+SIZE_T_SIZE);
    int idx;
    void *result,*bin,*bck,*fwd,*temp;
    
    if(newsize<=0x40)
    {
    	idx=get_f_idx(newsize);
    	bin=get_fbin(idx);
    	result=*(unsigned int*)(bin);
    	if(result && idx==get_f_idx(get_size(result)))
    	{
    		set(result+newsize,newsize);
    		*(unsigned int*)bin=get_fd(result);
	    	return result+8;
		}
    }
    if(if_in_small(newsize))
    {
        idx=get_s_idx(newsize);
        bin=get_smallbin(idx);
        bck=get_bk(bin);
        if(bin!=bck)
        {
    	    if(idx==get_s_idx(get_size(bck)))
    	    {
    		    //set(bck+newsize,newsize);
    		    my_unlink(bck);
                set_size(bck,pack(newsize,1));
	    	    return bck+8;
            }
		}
    }
	put_bins:
    bin=get_ubin();
	for(result=get_bk(bin);result!=bin;)
	{
		temp=get_bk(result);
		if(get_size(result)==newsize)
		{
			my_unlink(result);
			set_size(result,pack(newsize,1));    
			return result+8;
		}
		my_unlink(result);
		if(if_in_small(get_size(result)))//put into small bin
		{
			idx=get_s_idx(get_size(result));
			bck=get_smallbin(idx);
			fwd=get_fd(bck);
		}
		else//put into large bin
		{
			bck=get_largebin(get_size(result));
			fwd=get_fd(bck);
		 	if (fwd != bck)
    		{
				if(get_size(result)<get_size(get_bk(bck))-1)//smaller than the smallest
    			{
       				fwd=bck;
					bck=get_bk(bck);
     				set_fn(result,get_fd(fwd));
         			set_bn(result,get_bn(get_fd(fwd)));
					set_fn(get_bn(result),result);
					set_bn(get_fd(fwd),result);
     			}
				else
				{
					while (get_size(result) < get_size(fwd)-1)
					{
						fwd=get_fn(fwd);
      				}
					if (get_size(result) == get_size(fwd)-1)
					{
						fwd=get_fd(fwd);}
					else
					{
						set_fn(result,fwd);
						set_bn(result,get_bn(fwd));
						set_bn(fwd,result);
						set_fn(get_bn(result),result);
					}
					bck=get_bk(fwd);
				}
 			}
    		else//large bin is empty
    		{
				set_bn(result,result);
      			set_fn(result,result);
    		}
			set_size(result,pack(get_size(result),1));
		}
		set_bk(result,bck);
		set_fd(result,fwd);
		set_bk(fwd,result);
		set_fd(bck,result);
		result=temp;
	}
	for(bin=get_largebin(newsize);bin!=mem_head_end;bin=get_next_bin(bin))
	{
		fwd=get_fd(bin);
		if(bin != fwd && get_size(fwd)-1>=newsize)
		{
			for(bck=get_bk(bin);get_size(bck)==get_size(get_bk(bck));)
			{
				bck=get_bk(bck);		
			}
			for(;get_size(bck)-1<newsize;bck=get_bn(bck));
			
			if(get_size(get_fd(bck))==get_size(bck))
			bck=get_fd(bck);
			else
			{
				set_fn(get_bn(bck),get_fn(bck));
				set_bn(get_fn(bck),get_bn(bck));
			}
			if(get_size(bck)-1-newsize<=8)
			{
                
				my_unlink(bck);
				//set_size(bck,pack(get_size(bck),1));
				return bck+8;
			}
			else
			{
				my_unlink(bck);
				set(bck+get_size(bck)-1,get_size(bck)-1-newsize);
                set_size(bck+newsize,get_size(bck)-1-newsize);
				set_size(bck,pack(newsize,1));
				set(bck+newsize,newsize);
				result=bck;
				bck=result+newsize;
                
				bin=get_ubin();
				fwd=get_fd(bin);
				set_bk(fwd,bck);
				set_fd(bck,fwd);
				set_bk(bck,bin);
				set_fd(bin,bck);
				return result+8;
			}
		}
	}
	if(!if_in_small(newsize) && fastbin_not_empty())
	{
		fastbin_consolidate();
		goto put_bins;
	}
	if(top_chunk+newsize>mem_max_addr)
	{
		mem_sbrk(newsize+top_chunk-mem_max_addr);
		result=top_chunk;
		set_size(result,pack(newsize,1));
        set(result,0);
		mem_max_addr+=newsize+top_chunk-mem_max_addr;
		top_chunk=mem_max_addr;
	}
	else
	{
		result=top_chunk;
		set_size(result,pack(newsize,1));
        set(result,0);
		top_chunk+=newsize;
	}
	return result+8;
}

/*
 * mm_free - Freeing a block does nothing.
 */
void mm_free(void *ptr)
{
	char *p=ptr-8;
	int pre_inuse,post_inuse,size; 
	void *bin,*bck,*fwd;
	
	size=get_size(p)-1;
	if(size<=0x40 && !f_con)//put into fastbin
	{
		bin=get_fbin(get_f_idx(size));
		set(ptr,get(bin));
		set(bin,p);
		set(p+size,size);
		return;
	}
	pre_inuse=is_inuse(p-get(p));
	post_inuse=is_inuse(p+size);
	set_size(p,size);
	set(p+size,size);
	if(p+size==top_chunk)
	{
		if(!pre_inuse)
		{
			my_unlink(p-get(p));
			top_chunk=p-get(p);
		}
		else
		top_chunk=p;
	}
	else
	{
		if(!pre_inuse && !post_inuse)
		{
			my_unlink(p-get(p));
			my_unlink(p+get_size(p));
			size=get_size(p)+get_size(p-get(p))+get_size(p+get_size(p));
			p=p-get(p);
			set_size(p,size);
			set(p+size,size);
		}
		else if(!pre_inuse)
		{
			my_unlink(p-get(p));
			size=get_size(p)+get_size(p-get(p));
			p=p-get(p);
			set_size(p,size);
			set(p+size,size);
		}
		else if(!post_inuse)
		{
			my_unlink(p+get_size(p));
			size=get_size(p)+get_size(p+get_size(p));
			set_size(p,size);
			set(p+size,size);
		}
        bin=get_ubin();
		bck=p;
		fwd=get_fd(bin);
		set_bk(fwd,bck);
		set_fd(bck,fwd);
		set_bk(bck,bin);
		set_fd(bin,bck);
	}
}	

/*
 * mm_realloc - Implemented simply in terms of mm_malloc and mm_free
 */
void *mm_realloc(void *ptr, size_t size)
{
	void *p = ptr-8;
	void *newptr,*bin,*fwd;
	int newsize = ALIGN(size+SIZE_T_SIZE);
	size_t copySize;
	int pre_inuse,post_inuse,p_size,temp;
	
	p_size=get_size(p)-1;
	copySize=p_size-8;
	if(newsize>p_size)
	{
		pre_inuse=is_inuse(p-get(p)) || (get(p)==0);
		post_inuse=is_inuse(p+p_size);
		if(!pre_inuse)
		{
			p_size+=get_size(p-get(p));
			p=p-get(p);
			if(p_size>=newsize)
			{
                my_unlink(p);
                memcpy(p+8, ptr, copySize);
				if(p_size-newsize<=8)
				{
					newsize=p_size;
			 		set_size(p,pack(p_size,1));
					set(p+p_size,p_size);
				}
				else
				{
					set(p+p_size,p_size-newsize);
					set_size(p+newsize,p_size-newsize);
					set(p+newsize,newsize);
					set_size(p,pack(newsize,1));
                    bin=get_ubin();
                    fwd=get_fd(bin);
                    set_bk(fwd,p+newsize);
                    set_fd(bin,p+newsize);
                    set_fd(p+newsize,fwd);
                    set_bk(p+newsize,bin);
				}
				return p+8;
			}
		}
		if(!post_inuse)
		{
			if(p+p_size==top_chunk)
			{
				if(!pre_inuse)
				{
                    my_unlink(p);
                    memcpy(p+8, ptr, copySize);
                }
                if(mem_max_addr-top_chunk<newsize-p_size)
				{
                    mem_sbrk(newsize-p_size-(mem_max_addr-top_chunk));
				    set_size(p,pack(newsize,1));
				    //set(p+newsize,newsize);
				    mem_max_addr+=newsize-p_size-(mem_max_addr-top_chunk);
                    top_chunk=mem_max_addr;
                }
                else
                {
                    top_chunk+=newsize-p_size;
                    set_size(p,pack(newsize,1));
                }
				return p+8;
			}
			else
			{
				temp=p_size;
				p_size+=get_size(p+p_size);
				if(p_size>=newsize)
				{
                    my_unlink(p+temp);
                    if(!pre_inuse)
                    my_unlink(p);
					memcpy(p+8, ptr, copySize);
					if(p_size-newsize<=8)
					{
						newsize=p_size;
				 		set_size(p,pack(p_size,1));
						set(p+p_size,p_size);
					}
					else
					{
						set(p+p_size,p_size-newsize);
						set_size(p+newsize,p_size-newsize);
						set(p+newsize,newsize);
						set_size(p,pack(newsize,1));

                        bin=get_ubin();
                        fwd=get_fd(bin);
                        set_bk(fwd,p+newsize);
                        set_fd(bin,p+newsize);
                        set_fd(p+newsize,fwd);
                        set_bk(p+newsize,bin);
					}
					return p+8;
				}
			}
		}
		p = mm_malloc(size);
		memcpy(p, ptr, copySize);
		mm_free(ptr);
		return p;
	}
	else if(newsize<p_size-8)
	{
		set(p+p_size,p_size-newsize);
		set_size(p+newsize,p_size-newsize);
		set(p+newsize,newsize);
		set_size(p,pack(newsize,1));

        bin=get_ubin();
        fwd=get_fd(bin);
        set_bk(fwd,p+newsize);
        set_fd(bin,p+newsize);
        set_fd(p+newsize,fwd);
        set_bk(p+newsize,bin); 		
	}
	return p+8;
}