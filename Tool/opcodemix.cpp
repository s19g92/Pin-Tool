/*BEGIN_LEGAL 
Intel Open Source License 

Copyright (c) 2002-2017 Intel Corporation. All rights reserved.
 
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.  Redistributions
in binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.  Neither the name of
the Intel Corporation nor the names of its contributors may be used to
endorse or promote products derived from this software without
specific prior written permission.
 
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INTEL OR
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
END_LEGAL */
/* Modified by SHUBHAM GUPTA
*/
/*! @file
 *  This file contains a tool for Dynamic Binary Analysis
 *  for Systems Security Class Fall 2017.
 */

/* ===================================================================== */
/* Declarations */
/* ===================================================================== */

#include <vector>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <unistd.h>
#include "pin.H"
#include "control_manager.H"

/* ===================================================================== */
/* Names of malloc and free */
/* ===================================================================== */
#if defined(TARGET_MAC)
#define MALLOC "_malloc"
#define FREE "_free"
#else
#define MALLOC "malloc"
#define FREE "free"
#endif 


#if defined(TARGET_MAC)
#include <sys/syscall.h>
#else
#include <syscall.h>
#endif

UINT64 ins_count = 0;

using namespace std;
using namespace CONTROLLER;


ofstream TraceFile;
ofstream trace;
static std::ofstream* part1 = new std::ofstream("part_1.out"); // For Part 1;
static std::ofstream* part2 = new std::ofstream("part_2.out"); // For Part 2;
static std::ofstream* part3 = new std::ofstream("part_3.out"); // For Part 3;
static std::ofstream* part4 = new std::ofstream("part_4.out"); // For Part 4;
static std::ofstream* part5 = new std::ofstream("part_5.out"); // For Part 5;
static std::ofstream* part6 = new std::ofstream("part_6.out"); // For Part 6;

/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

KNOB<BOOL>   KnobPid(KNOB_MODE_WRITEONCE,                "pintool",
    "i", "0", "append pid to output");
KNOB<BOOL>   KnobPrintArgs(KNOB_MODE_WRITEONCE, "pintool", "a", "0", "print call arguments ");
KNOB<BOOL>   KnobProfilePredicated(KNOB_MODE_WRITEONCE,  "pintool",
    "p", "0", "enable accurate profiling for predicated instructions");
KNOB<BOOL>   KnobProfileStaticOnly(KNOB_MODE_WRITEONCE,  "pintool",
    "s", "0", "terminate after collection of static profile for main image");
#ifndef TARGET_WINDOWS
KNOB<BOOL>   KnobProfileDynamicOnly(KNOB_MODE_WRITEONCE, "pintool",
    "d", "0", "Only collect dynamic profile");
#else
KNOB<BOOL>   KnobProfileDynamicOnly(KNOB_MODE_WRITEONCE, "pintool",
    "d", "1", "Only collect dynamic profile");
#endif
KNOB<BOOL>   KnobNoSharedLibs(KNOB_MODE_WRITEONCE,       "pintool",
    "no_shared_libs", "0", "do not instrument shared libraries");

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    cerr <<
        "This is a pin tool for Dynamic Binary Analysis for Systems Security Class Fall 2017.\n"
        "\n";

    cerr << KNOB_BASE::StringKnobSummary();

    cerr << endl;

    return -1;
}

/* ===================================================================== */
/* INDEX HELPERS */
/* ===================================================================== */

const UINT32 MAX_INDEX = 4096;
const UINT32 INDEX_SPECIAL =  3000;
const UINT32 MAX_MEM_SIZE = 512;


const UINT32 INDEX_TOTAL =          INDEX_SPECIAL + 0;
const UINT32 INDEX_MEM_ATOMIC =     INDEX_SPECIAL + 1;
const UINT32 INDEX_STACK_READ =     INDEX_SPECIAL + 2;
const UINT32 INDEX_STACK_WRITE =    INDEX_SPECIAL + 3;
const UINT32 INDEX_IPREL_READ =     INDEX_SPECIAL + 4;
const UINT32 INDEX_IPREL_WRITE =    INDEX_SPECIAL + 5;
const UINT32 INDEX_MEM_READ_SIZE =  INDEX_SPECIAL + 6;
const UINT32 INDEX_MEM_WRITE_SIZE = INDEX_SPECIAL + 6 + MAX_MEM_SIZE;
const UINT32 INDEX_SPECIAL_END   =  INDEX_SPECIAL + 6 + MAX_MEM_SIZE + MAX_MEM_SIZE;


BOOL IsMemReadIndex(UINT32 i)
{
    return (INDEX_MEM_READ_SIZE <= i && i < INDEX_MEM_READ_SIZE + MAX_MEM_SIZE );
}

BOOL IsMemWriteIndex(UINT32 i)
{
    return (INDEX_MEM_WRITE_SIZE <= i && i < INDEX_MEM_WRITE_SIZE + MAX_MEM_SIZE );
}


/* =========================== PART 1 ================================== */
VOID do_ins_count()
{
    ins_count++;
}

/* ===================================================================== */

VOID Instruction(INS ins, VOID *v)
{
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)do_ins_count, IARG_END);
}

/* =========================== END PART 1 ============================== */


/* =========================== PART 2 ================================== */
// Pin calls this function every time a new img is loaded
// It can instrument the image, but this example does not
// Note that imgs (including shared libraries) are loaded lazily

VOID ImageLoad(IMG img, VOID *v)
{
    *part2 << "Loading " << IMG_Name(img) << ", Image id = " << IMG_Id(img) << endl;
}

// Pin calls this function every time a new img is unloaded
// You can't instrument an image that is about to be unloaded
VOID ImageUnload(IMG img, VOID *v)
{
    *part2 << "Unloading " << IMG_Name(img) << endl;
}

/* =========================== END PART 2 ============================== */

/* ============================ PART 3 ================================= */

LOCALFUN UINT32 INS_GetIndex(INS ins)
{
    if( INS_IsPredicated(ins) )
        return MAX_INDEX + INS_Opcode(ins);
    else
        return INS_Opcode(ins);
}

/* ===================================================================== */

LOCALFUN  UINT32 IndexStringLength(BBL bbl, BOOL memory_acess_profile)
{
    UINT32 count = 0;

    for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
    {
        count++;
        if( memory_acess_profile )
        {
            if( INS_IsMemoryRead(ins) ) count++;   // for size

            if( INS_IsStackRead(ins) ) count++;

            if( INS_IsIpRelRead(ins) ) count++;


            if( INS_IsMemoryWrite(ins) ) count++; // for size

            if( INS_IsStackWrite(ins) ) count++;

            if( INS_IsIpRelWrite(ins) ) count++;


            if( INS_IsAtomicUpdate(ins) ) count++;
        }
    }

    return count;
}


/* ===================================================================== */
LOCALFUN UINT32 MemsizeToIndex(UINT32 size, BOOL write)
{
    return (write ? INDEX_MEM_WRITE_SIZE : INDEX_MEM_READ_SIZE ) + size;
}

/* ===================================================================== */
LOCALFUN UINT16 *INS_GenerateIndexString(INS ins, UINT16 *stats, BOOL memory_acess_profile)
{
    *stats++ = INS_GetIndex(ins);

    if( memory_acess_profile )
    {
        if( INS_IsMemoryRead(ins) )  *stats++ = MemsizeToIndex( INS_MemoryReadSize(ins), 0 );
        if( INS_IsMemoryWrite(ins) ) *stats++ = MemsizeToIndex( INS_MemoryWriteSize(ins), 1 );

        if( INS_IsAtomicUpdate(ins) ) *stats++ = INDEX_MEM_ATOMIC;

        if( INS_IsStackRead(ins) ) *stats++ = INDEX_STACK_READ;
        if( INS_IsStackWrite(ins) ) *stats++ = INDEX_STACK_WRITE;

        if( INS_IsIpRelRead(ins) ) *stats++ = INDEX_IPREL_READ;
        if( INS_IsIpRelWrite(ins) ) *stats++ = INDEX_IPREL_WRITE;
    }

    return stats;
}


/* ===================================================================== */

LOCALFUN string IndexToOpcodeString( UINT32 index )
{
    if( INDEX_SPECIAL <= index  && index < INDEX_SPECIAL_END)
    {
        if( index == INDEX_TOTAL )            return  "*total";
        else if( IsMemReadIndex(index) )      return  "*mem-read-" + decstr( index - INDEX_MEM_READ_SIZE );
        else if( IsMemWriteIndex(index))      return  "*mem-write-" + decstr( index - INDEX_MEM_WRITE_SIZE );
        else if( index == INDEX_MEM_ATOMIC )  return  "*mem-atomic";
        else if( index == INDEX_STACK_READ )  return  "*stack-read";
        else if( index == INDEX_STACK_WRITE ) return  "*stack-write";
        else if( index == INDEX_IPREL_READ )  return  "*iprel-read";
        else if( index == INDEX_IPREL_WRITE ) return  "*iprel-write";

        else
        {
            ASSERTX(0);
            return "";
        }
    }
    else
    {
        return OPCODE_StringShort(index);
    }

}

/* ===================================================================== */
typedef UINT64 COUNTER;


/* zero initialized */

class STATS
{
  public:
    COUNTER unpredicated[MAX_INDEX];
    COUNTER predicated[MAX_INDEX];
    COUNTER predicated_true[MAX_INDEX];

    VOID Clear()
    {
        for ( UINT32 i = 0; i < MAX_INDEX; i++)
        {
            unpredicated[i] = 0;
            predicated[i] = 0;
            predicated_true[i] = 0;
        }
    }
};


STATS GlobalStatsStatic;
STATS GlobalStatsDynamic;

class BBLSTATS
{
  public:
    COUNTER _counter;
    const UINT16 * const _stats;

  public:
    BBLSTATS(UINT16 * stats) : _counter(0), _stats(stats) {};

};

LOCALVAR vector<const BBLSTATS*> statsList;

/* ===================================================================== */

LOCALVAR UINT32 enabled = 0;

LOCALFUN VOID Handler(EVENT_TYPE ev, VOID *val, CONTEXT * ctxt, VOID *ip, THREADID tid, bool bcast)
{
    switch(ev)
    {
      case EVENT_START:
        enabled = 1;
        break;

      case EVENT_STOP:
        enabled = 0;
        break;

      default:
        ASSERTX(false);
    }
}

LOCALVAR CONTROL_MANAGER control;

/* ===================================================================== */

VOID PIN_FAST_ANALYSIS_CALL docount(COUNTER * counter)
{
    (*counter) += enabled;
}

/* ===================================================================== */

VOID Trace(TRACE trace, VOID *v)
{
    if ( KnobNoSharedLibs.Value()
         && IMG_Type(SEC_Img(RTN_Sec(TRACE_Rtn(trace)))) == IMG_TYPE_SHAREDLIB)
        return;

    const BOOL accurate_handling_of_predicates = KnobProfilePredicated.Value();

    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        const INS head = BBL_InsHead(bbl);
        if (! INS_Valid(head)) continue;

        // Summarize the stats for the bbl in a 0 terminated list
        // This is done at instrumentation time
        const UINT32 n = IndexStringLength(bbl, 1);

        UINT16 *const stats = new UINT16[ n + 1];
        UINT16 *const stats_end = stats + (n + 1);
        UINT16 *curr = stats;

        for (INS ins = head; INS_Valid(ins); ins = INS_Next(ins))
        {
            // Count the number of times a predicated instruction is actually executed
            // this is expensive and hence disabled by default
            if( INS_IsPredicated(ins) && accurate_handling_of_predicates )
            {
                INS_InsertPredicatedCall(ins,
                                         IPOINT_BEFORE,
                                         AFUNPTR(docount),
                                         IARG_PTR, &(GlobalStatsDynamic.predicated_true[INS_Opcode(ins)]),
                                         IARG_END);
            }

            curr = INS_GenerateIndexString(ins,curr,1);
        }

        // string terminator
        *curr++ = 0;

        ASSERTX( curr == stats_end );


        // Insert instrumentation to count the number of times the bbl is executed
        BBLSTATS * bblstats = new BBLSTATS(stats);
        INS_InsertCall(head, IPOINT_BEFORE, AFUNPTR(docount), IARG_FAST_ANALYSIS_CALL, IARG_PTR, &(bblstats->_counter), IARG_END);

        // Remember the counter and stats so we can compute a summary at the end
        statsList.push_back(bblstats);
    }
}

/* ===================================================================== */
VOID DumpStats(ofstream& out, STATS& stats, BOOL predicated_true,  const string& title)
{
    out <<
        "#\n"
        "# " << title << "\n"
        "#\n"
        "#     opcode       count-unpredicated    count-predicated";

    if( predicated_true )
        out << "    count-predicated-true";

    out << "\n#\n";

    for ( UINT32 i = 0; i < INDEX_TOTAL; i++)
    {
        stats.unpredicated[INDEX_TOTAL] += stats.unpredicated[i];
        stats.predicated[INDEX_TOTAL] += stats.predicated[i];
        stats.predicated_true[INDEX_TOTAL] += stats.predicated_true[i];
    }

    for ( UINT32 i = 0; i < MAX_INDEX; i++)
    {
        if( stats.unpredicated[i] == 0 &&
            stats.predicated[i] == 0 ) continue;

        out << setw(4) << i << " " <<  ljstr(IndexToOpcodeString(i),15) << " " <<
            setw(16) << stats.unpredicated[i] << " " <<
            setw(16) << stats.predicated[i];
        if( predicated_true ) out << " " << setw(16) << stats.predicated_true[i];
        out << endl;
    }
}
/* ========================= END PART 3 ================================ */

/* ============================ PART 4 ================================= */
string invalid = "invalid_rtn";

/* ===================================================================== */
const string *Target2String(ADDRINT target)
{
    string name = RTN_FindNameByAddress(target);
    if (name == "")
        return &invalid;
    else
        return new string(name);
}

/* ===================================================================== */

VOID  do_call_args(const string *s, ADDRINT arg0)
{
    *part4 << *s << "(" << arg0 << ",...)" << endl;
}

/* ===================================================================== */

VOID  do_call_args_indirect(ADDRINT target, BOOL taken, ADDRINT arg0)
{
    if( !taken ) return;
    
    const string *s = Target2String(target);
    do_call_args(s, arg0);

    if (s != &invalid)
        delete s;
}

/* ===================================================================== */

VOID  do_call(const string *s)
{
    *part4 << *s << endl;
}

/* ===================================================================== */

VOID  do_call_indirect(ADDRINT target, BOOL taken)
{
    if( !taken ) return;

    const string *s = Target2String(target);
    do_call( s );
    
    if (s != &invalid)
        delete s;
}

/* ===================================================================== */

VOID Trace_call(TRACE trace, VOID *v)
{
    const BOOL print_args = KnobPrintArgs.Value();
    
        
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        INS tail = BBL_InsTail(bbl);
        
        if( INS_IsCall(tail) )
        {
            if( INS_IsDirectBranchOrCall(tail) )
            {
                const ADDRINT target = INS_DirectBranchOrCallTargetAddress(tail);
                if( print_args )
                {
                    INS_InsertPredicatedCall(tail, IPOINT_BEFORE, AFUNPTR(do_call_args),
                                             IARG_PTR, Target2String(target), IARG_FUNCARG_CALLSITE_VALUE, 0, IARG_END);
                }
                else
                {
                    INS_InsertPredicatedCall(tail, IPOINT_BEFORE, AFUNPTR(do_call),
                                             IARG_PTR, Target2String(target), IARG_END);
                }
                
            }
            else
            {
                if( print_args )
                {
                    INS_InsertCall(tail, IPOINT_BEFORE, AFUNPTR(do_call_args_indirect),
                                   IARG_BRANCH_TARGET_ADDR, IARG_BRANCH_TAKEN,  IARG_FUNCARG_CALLSITE_VALUE, 0, IARG_END);
                }
                else
                {
                    INS_InsertCall(tail, IPOINT_BEFORE, AFUNPTR(do_call_indirect),
                                   IARG_BRANCH_TARGET_ADDR, IARG_BRANCH_TAKEN, IARG_END);
                }
                
                
            }
        }
        else
        {
            // sometimes code is not in an image
            RTN rtn = TRACE_Rtn(trace);
            
            // also track stup jumps into share libraries
            if( RTN_Valid(rtn) && !INS_IsDirectBranchOrCall(tail) && ".plt" == SEC_Name( RTN_Sec( rtn ) ))
            {
                if( print_args )
                {
                    INS_InsertCall(tail, IPOINT_BEFORE, AFUNPTR(do_call_args_indirect),
                                   IARG_BRANCH_TARGET_ADDR, IARG_BRANCH_TAKEN,  IARG_FUNCARG_CALLSITE_VALUE, 0, IARG_END);
                }
                else
                {
                    INS_InsertCall(tail, IPOINT_BEFORE, AFUNPTR(do_call_indirect),
                                   IARG_BRANCH_TARGET_ADDR, IARG_BRANCH_TAKEN, IARG_END);

                }
            }
        }
        
    }
}
/* ========================= END PART 4 ================================ */

/* ============================ PART 5 ================================= */

/* ===================================================================== */
/* Analysis routines                                                     */
/* ===================================================================== */
 
VOID Arg1Before(CHAR * name, ADDRINT size)
{
    *part5 << name << "(" << size << ")" << endl;
}

VOID MallocAfter(ADDRINT ret)
{
    *part5 << "  returns " << ret << endl;
}


/* ===================================================================== */
/* Instrumentation routines                                              */
/* ===================================================================== */
   
VOID Image_malloc(IMG img, VOID *v)
{
    // Instrument the malloc() and free() functions.  Print the input argument
    // of each malloc() or free(), and the return value of malloc().
    //
    //  Find the malloc() function.
    RTN mallocRtn = RTN_FindByName(img, MALLOC);
    if (RTN_Valid(mallocRtn))
    {
        RTN_Open(mallocRtn);

        // Instrument malloc() to print the input argument value and the return value.
        RTN_InsertCall(mallocRtn, IPOINT_BEFORE, (AFUNPTR)Arg1Before,
                       IARG_ADDRINT, MALLOC,
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                       IARG_END);
        RTN_InsertCall(mallocRtn, IPOINT_AFTER, (AFUNPTR)MallocAfter,
                       IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

        RTN_Close(mallocRtn);
    }

    // Find the free() function.
    RTN freeRtn = RTN_FindByName(img, FREE);
    if (RTN_Valid(freeRtn))
    {
        RTN_Open(freeRtn);
        // Instrument free() to print the input argument value.
        RTN_InsertCall(freeRtn, IPOINT_BEFORE, (AFUNPTR)Arg1Before,
                       IARG_ADDRINT, FREE,
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                       IARG_END);
        RTN_Close(freeRtn);
    }
}

/* ========================= END PART 5 ================================ */

/* =========================== PART 6 ================================== */

// Print syscall number and arguments
VOID SysBefore(ADDRINT ip, ADDRINT num, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2,
               ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
#if defined(TARGET_IA32)
    // On ia32, there are only 5 registers for passing system call arguments,
    // but mmap needs 6. For mmap on ia32, the first argument to the system call
    // is a pointer to an array of the 6 arguments
    if (num == SYS_mmap)
    {
        ADDRINT * mmapArgs = &arg0;
        arg0 = mmapArgs[0];
        arg1 = mmapArgs[1];
        arg2 = mmapArgs[2];
        arg3 = mmapArgs[3];
        arg4 = mmapArgs[4];
        arg5 = mmapArgs[5];
    }
#endif

    // ALL system calls have fixed decimal number assigned.
    /*   #define __NR_exit                 1
     *   #define __NR_fork                 2
     *   #define __NR_read                 3
     *   #define __NR_write                4
     *   #define __NR_open                 5
     *   #define __NR_close                6
     *   #define __NR_waitpid              7
     *   #define __NR_creat                8
     *   #define __NR_link                 9
     *   #define __NR_unlink              10
     *   #define __NR_execve              11
     *   #define __NR_chdir               12
     *   #define __NR_time                13
     *   #define __NR_mknod               14
     *   #define __NR_chmod               15
     *   #define __NR_lchown              16
     *   and so on 
    */


     switch(num) {
        case 0: *part6 << "@ip 0x" << hex << ip << ":  SETUP sys call " << dec << num;
                *part6 << "(0x" << hex << arg0 << ", 0x" << arg1 << ", 0x" << arg2;
                *part6 << hex << ", 0x" << arg3 << ", 0x" << arg4 << ", 0x" << arg5 << ")" << endl;
                break;        

        case 1: *part6 << "@ip 0x" << hex << ip << ":  EXIT sys call " << dec << num;
                *part6 << "(0x" << hex << arg0 << ", 0x" << arg1 << ", 0x" << arg2;
                *part6 << hex << ", 0x" << arg3 << ", 0x" << arg4 << ", 0x" << arg5 << ")" << endl;
                break;

        case 2: *part6 << "@ip 0x" << hex << ip << ": FORK sys call " << dec << num;
                *part6 << "(0x" << hex << arg0 << ", 0x" << arg1 << ", 0x" << arg2;
                *part6 << hex << ", 0x" << arg3 << ", 0x" << arg4 << ", 0x" << arg5 << ")" << endl;
                break;

        case 3: *part6 << "@ip 0x" << hex << ip << ": READ sys call " << dec << num;
                *part6 << "(0x" << hex << arg0 << ", 0x" << arg1 << ", 0x" << arg2;
                *part6 << hex << ", 0x" << arg3 << ", 0x" << arg4 << ", 0x" << arg5 << ")" << endl;
                break;

        case 4: *part6 << "@ip 0x" << hex << ip << ": WRITE sys call " << dec << num;
                *part6 << "(0x" << hex << arg0 << ", 0x" << arg1 << ", 0x" << arg2;
                *part6 << hex << ", 0x" << arg3 << ", 0x" << arg4 << ", 0x" << arg5 << ")" << endl;
                break;

        case 5: *part6 << "@ip 0x" << hex << ip << ": OPEN sys call " << dec << num;
                *part6 << "(0x" << hex << arg0 << ", 0x" << arg1 << ", 0x" << arg2;
                *part6 << hex << ", 0x" << arg3 << ", 0x" << arg4 << ", 0x" << arg5 << ")" << endl;
                break;

        case 6: *part6 << "@ip 0x" << hex << ip << ": CLOSE sys call " << dec << num;
                *part6 << "(0x" << hex << arg0 << ", 0x" << arg1 << ", 0x" << arg2;
                *part6 << hex << ", 0x" << arg3 << ", 0x" << arg4 << ", 0x" << arg5 << ")" << endl;
                break;

        case 7: *part6 << "@ip 0x" << hex << ip << ": WAITPID sys call " << dec << num;
                *part6 << "(0x" << hex << arg0 << ", 0x" << arg1 << ", 0x" << arg2;
                *part6 << hex << ", 0x" << arg3 << ", 0x" << arg4 << ", 0x" << arg5 << ")" << endl;
                break;

        case 8: *part6 << "@ip 0x" << hex << ip << ": CREAT sys call " << dec << num;
                *part6 << "(0x" << hex << arg0 << ", 0x" << arg1 << ", 0x" << arg2;
                *part6 << hex << ", 0x" << arg3 << ", 0x" << arg4 << ", 0x" << arg5 << ")" << endl;
                break;

        case 9: *part6 << "@ip 0x" << hex << ip << ": LINK sys call " << dec << num;
                *part6 << "(0x" << hex << arg0 << ", 0x" << arg1 << ", 0x" << arg2;
                *part6 << hex << ", 0x" << arg3 << ", 0x" << arg4 << ", 0x" << arg5 << ")" << endl;
                break;

        case 10: *part6 << "@ip 0x" << hex << ip << ": UNLINK sys call " << dec << num;
                *part6 << "(0x" << hex << arg0 << ", 0x" << arg1 << ", 0x" << arg2;
                *part6 << hex << ", 0x" << arg3 << ", 0x" << arg4 << ", 0x" << arg5 << ")" << endl;
                break;

        case 11: *part6 << "@ip 0x" << hex << ip << ": EXECVE sys call " << dec << num;
                *part6 << "(0x" << hex << arg0 << ", 0x" << arg1 << ", 0x" << arg2;
                *part6 << hex << ", 0x" << arg3 << ", 0x" << arg4 << ", 0x" << arg5 << ")" << endl;
                break;

        case 12: *part6 << "@ip 0x" << hex << ip << ": CHDIR sys call " << dec << num;
                *part6 << "(0x" << hex << arg0 << ", 0x" << arg1 << ", 0x" << arg2;
                *part6 << hex << ", 0x" << arg3 << ", 0x" << arg4 << ", 0x" << arg5 << ")" << endl;
                break;

        case 13: *part6 << "@ip 0x" << hex << ip << ": TIME sys call " << dec << num;
                *part6 << "(0x" << hex << arg0 << ", 0x" << arg1 << ", 0x" << arg2;
                *part6 << hex << ", 0x" << arg3 << ", 0x" << arg4 << ", 0x" << arg5 << ")" << endl;
                break;

        case 14: *part6 << "@ip 0x" << hex << ip << ": MKNOD sys call " << dec << num;
                *part6 << "(0x" << hex << arg0 << ", 0x" << arg1 << ", 0x" << arg2;
                *part6 << hex << ", 0x" << arg3 << ", 0x" << arg4 << ", 0x" << arg5 << ")" << endl;
                break;

        case 15: *part6 << "@ip 0x" << hex << ip << ": CHMOD sys call " << dec << num;
                *part6 << "(0x" << hex << arg0 << ", 0x" << arg1 << ", 0x" << arg2;
                *part6 << hex << ", 0x" << arg3 << ", 0x" << arg4 << ", 0x" << arg5 << ")" << endl;
                break;

        case 16: *part6 << "@ip 0x" << hex << ip << ": LCHOWN sys call " << dec << num;
                *part6 << "(0x" << hex << arg0 << ", 0x" << arg1 << ", 0x" << arg2;
                *part6 << hex << ", 0x" << arg3 << ", 0x" << arg4 << ", 0x" << arg5 << ")" << endl;
                break;

        case 21: *part6 << "@ip 0x" << hex << ip << ":  MOUNT sys call " << dec << num;
                *part6 << "(0x" << hex << arg0 << ", 0x" << arg1 << ", 0x" << arg2;
                *part6 << hex << ", 0x" << arg3 << ", 0x" << arg4 << ", 0x" << arg5 << ")" << endl;
                break;

        case 22: *part6 << "@ip 0x" << hex << ip << ":  UNMOUNT sys call " << dec << num;
                *part6 << "(0x" << hex << arg0 << ", 0x" << arg1 << ", 0x" << arg2;
                *part6 << hex << ", 0x" << arg3 << ", 0x" << arg4 << ", 0x" << arg5 << ")" << endl;
                break;

        case 33: *part6 << "@ip 0x" << hex << ip << ":  ACCESS sys call " << dec << num;
                *part6 << "(0x" << hex << arg0 << ", 0x" << arg1 << ", 0x" << arg2;
                *part6 << hex << ", 0x" << arg3 << ", 0x" << arg4 << ", 0x" << arg5 << ")" << endl;
                break;

        case 137: *part6 << "@ip 0x" << hex << ip << ":  AFS sys call " << dec << num;
                *part6 << "(0x" << hex << arg0 << ", 0x" << arg1 << ", 0x" << arg2;
                *part6 << hex << ", 0x" << arg3 << ", 0x" << arg4 << ", 0x" << arg5 << ")" << endl;
                break;

        default: *part6 << "@ip 0x" << hex << ip << ": sys call " << dec << num;
                *part6 << "(0x" << hex << arg0 << ", 0x" << arg1 << ", 0x" << arg2;
                *part6 << hex << ", 0x" << arg3 << ", 0x" << arg4 << ", 0x" << arg5 << ")" << endl;
                break;
     }
    
}


// Print the return value of the system call
VOID SysAfter( ADDRINT value, INT32 err, UINT32 gax )
{
    int error = 0;
    ADDRINT neg_one = (ADDRINT)(0-1);

    if ( err == 0 )
    {
        if ( gax != value )
            error = 1;
    }
    else
    {
        if ( value != neg_one )
            error = 3;
        if ( err != -(INT32)gax )
            error = 4;
    }

    if ( error == 0 )
        *part6 << "Success: value=0x" << hex << value << ", errno=" << dec << err << endl;
    else
    {
        *part6 << "Failure " << error << ": value=0x" << hex << value << ", errno=" << dec << err;
        *part6 << ", gax=0x" << hex << gax << endl;
    }

    *part6 << endl;
}

VOID SyscallEntry(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
    SysBefore(PIN_GetContextReg(ctxt, REG_INST_PTR),
        PIN_GetSyscallNumber(ctxt, std),
        PIN_GetSyscallArgument(ctxt, std, 0),
        PIN_GetSyscallArgument(ctxt, std, 1),
        PIN_GetSyscallArgument(ctxt, std, 2),
        PIN_GetSyscallArgument(ctxt, std, 3),
        PIN_GetSyscallArgument(ctxt, std, 4),
        PIN_GetSyscallArgument(ctxt, std, 5));
}

VOID SyscallExit(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
    SysAfter(PIN_GetSyscallReturn(ctxt, std),
             PIN_GetSyscallErrno(ctxt, std),
             PIN_GetContextReg(ctxt, REG_GAX));
}


// Is called for every instruction and instruments syscalls
VOID Instruction_syscall(INS ins, VOID *v)
{
    // For O/S's (Mac) that don't support PIN_AddSyscallEntryFunction(),
    // instrument the system call instruction.

    if (INS_IsSyscall(ins) && INS_HasFallThrough(ins))
    {
        // Arguments and syscall number is only available before
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SysBefore),
                       IARG_INST_PTR, IARG_SYSCALL_NUMBER,
                       IARG_SYSARG_VALUE, 0, IARG_SYSARG_VALUE, 1,
                       IARG_SYSARG_VALUE, 2, IARG_SYSARG_VALUE, 3,
                       IARG_SYSARG_VALUE, 4, IARG_SYSARG_VALUE, 5,
                       IARG_END);

        // return value only available after
        INS_InsertCall(ins, IPOINT_AFTER, AFUNPTR(SysAfter),
                       IARG_SYSRET_VALUE, IARG_SYSRET_ERRNO,
                       IARG_REG_VALUE, REG_GAX,
                       IARG_END);
    }
}


/* ========================= END PART 6 ================================ */

/* ============================ FINAL ================================== */

VOID Fini(int, VOID * v)
{   
    // Begin Output for Part 1  
    *part1 << "Number of Instructions: " << ins_count << endl;
    *part1 << "# $eof" <<  endl;

    part1->close();
    // End of Output for Part 1

    // Begin Part 2
    if (part2->is_open()) { part2->close(); }
    // End of Part 2

    // Begin Output for Part 3  
    // static counts 

    DumpStats(*part3, GlobalStatsStatic, false, "$static-counts");

    *part3 << endl;

    // dynamic Counts

    statsList.push_back(0); // add terminator marker

    for (vector<const BBLSTATS*>::iterator bi = statsList.begin(); bi != statsList.end(); bi++)
    {
        const BBLSTATS *b = (*bi);

        if ( b == 0 ) continue;

        for (const UINT16 * stats = b->_stats; *stats; stats++)
        {
            GlobalStatsDynamic.unpredicated[*stats] += b->_counter;
        }
    }

    DumpStats(*part3, GlobalStatsDynamic, KnobProfilePredicated, "$dynamic-counts");

    *part3 << "# $eof" <<  endl;

    part3->close();
    // End of Output for Part 3

    // Begin Output for Part 4
    *part4 << "# eof" << endl;  
    part4->close();
    // End of Output for Part 4

    // Begin Part 5
    if (part5->is_open()) { part5->close(); }
    // End of Part 5

    // Begin Output for Part 6
    *part6 << "#eof" << endl;
    part6->close();
    // End of Output for Part 6
}


/* ======================== END OF FINAL =============================== */

VOID Image(IMG img, VOID * v)
{
    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {
            // Prepare for processing of RTN, an  RTN is not broken up into BBLs,
            // it is merely a sequence of INSs
            RTN_Open(rtn);

            for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
            {
                UINT16 array[128];
                UINT16 *end  = INS_GenerateIndexString(ins,array,1);

                if( INS_IsPredicated(ins) )
                {
                    for( UINT16 *start= array; start < end; start++) GlobalStatsStatic.predicated[ *start ]++;
                }
                else
                {
                    for( UINT16 *start= array; start < end; start++) GlobalStatsStatic.unpredicated[ *start ]++;
                }
            }

            // to preserve space, release data associated with RTN after we have processed it
            RTN_Close(rtn);
        }
    }

    if( KnobProfileStaticOnly.Value() )
    {
        Fini(0,0);
        exit(0);
    }
}


/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, CHAR *argv[])
{
    PIN_InitSymbols();

    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }

    control.RegisterHandler(Handler, 0, FALSE);
    control.Activate();
    
    INS_AddInstrumentFunction(Instruction, 0);           // Count for Part 1         

    // Register ImageLoad to be called when an image is loaded
    IMG_AddInstrumentFunction(ImageLoad, 0);             // Images for Part 2

    // Register ImageUnload to be called when an image is unloaded
    IMG_AddUnloadFunction(ImageUnload, 0);

    TRACE_AddInstrumentFunction(Trace, 0);               // Trace for Part 3

    *part4 << hex;                                  

    part4->setf(ios::showbase);
    
    string trace_header = string("#\n"
                                 "# Call Trace Generated By Pin\n"
                                 "#\n");
    

    part4->write(trace_header.c_str(),trace_header.size());
    
    TRACE_AddInstrumentFunction(Trace_call, 0);             // Trace for Part 4

    *part5 << hex;
    part5->setf(ios::showbase);
    
    // Register Image to be called to instrument functions.
    IMG_AddInstrumentFunction(Image_malloc, 0);             // Trace Malloc for Part 5

    INS_AddInstrumentFunction(Instruction_syscall, 0);      // Trace System Calls for Part 6
    PIN_AddSyscallEntryFunction(SyscallEntry, 0);
    PIN_AddSyscallExitFunction(SyscallExit, 0);

    PIN_AddFiniFunction(Fini, 0);

    if( !KnobProfileDynamicOnly.Value() )
        IMG_AddInstrumentFunction(Image, 0);

    // Never returns

    PIN_StartProgram();

    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
