#include "pin.H"
#include <iostream>
#include <fstream>

#include "PinLocker.h"
#include "TraceLog.h"

#define UNKNOWN_ADDR ~ADDRINT(0)

using std::cerr;
using std::endl;
using std::string;

/* ================================================================== */
// Global variables
/* ================================================================== */

// RVAs relative to: serpentine4_p1.exe
ADDRINT g_disasmStart = 0x10aa000;
ADDRINT g_disasmStop = 0x1121DEA;

bool g_Test = false;

TraceLog traceLog;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */

KNOB< BOOL > KnobCheck(KNOB_MODE_WRITEONCE, "pintool", "c", "",
                       "Check characters positions in string. Requires running with a test string as an argument");

/* ===================================================================== */
// Utilities
/* ===================================================================== */

/*!
 *  Print out help message.
 */
INT32 Usage()
{
    cerr << "This tool prints out the number of dynamically executed " << endl
         << "instructions, basic blocks and threads in the application." << endl
         << endl;

    cerr << KNOB_BASE::StringKnobSummary() << endl;

    return -1;
}



ADDRINT get_mod_base(ADDRINT Address)
{
    if (Address == UNKNOWN_ADDR) {
        return UNKNOWN_ADDR;
    }
    IMG img = IMG_FindByAddress(Address);
    if (IMG_Valid(img)) {
        ADDRINT base = IMG_LoadOffset(img);
        if (base == 0) {
            base = IMG_LowAddress(img);
        }
        return base;
    }
    return UNKNOWN_ADDR;
}



/* ===================================================================== */
// Analysis routines
/* ===================================================================== */

inline ADDRINT getReturnFromTheStack(const CONTEXT* ctx)
{
    if (!ctx) return UNKNOWN_ADDR;

    ADDRINT retAddr = UNKNOWN_ADDR;
    const ADDRINT* stackPtr = reinterpret_cast<ADDRINT*>(PIN_GetContextReg(ctx, REG_STACK_PTR));
    size_t copiedSize = PIN_SafeCopy(&retAddr, stackPtr, sizeof(retAddr));
    if (copiedSize != sizeof(retAddr)) {
        return UNKNOWN_ADDR;
    }
    return retAddr;
}

int getValIndx(ADDRINT rax)
{
    char str[] = "0123456789ABCDEFabcdefghijklmopq";
    const size_t len = strlen(str);
    for (int i = 0; i < len; i++) {
        if (rax == ADDRINT(str[i])) return i;
    }
    return (-1);
}

void printArithm(std::stringstream& s1, const ADDRINT& val1, const ADDRINT& val2)
{
    {
        ADDRINT diff = val2 - val1;
        diff &= 0x0FFFFFFFF;
        s1 << "res += 0x" << diff;//<< "#[ " << val2 << " - " << val1 << " ]";
    }
    s1 << " ; ";
    {
        ADDRINT diff = val1 - val2;
        diff &= 0x0FFFFFFFF;
        s1 << "res -= 0x" << diff;// << "#[ " << val1 << " - " << val2 << " ]";
    }
    s1 << " ; ";
    {
        ADDRINT diff = val2 ^ val1;
        diff &= 0x0FFFFFFFF;
        s1 << " res ^= 0x" << diff;
    }
}

void printDifference(std::stringstream& mS, const ADDRINT& changedTracked, const ADDRINT& changed)
{
    std::stringstream s1;
    if (!changedTracked) {
        return;
    }
    s1 << std::hex;
    s1 << "#[ ";
    printArithm(s1, changedTracked, changed);
    s1 << " ] ";
    mS << " UNK: " << s1.str();

    traceLog.logListingLine(s1.str());
}

std::string dumpContext(const std::string& disasm, const CONTEXT* ctx)
{
    std::stringstream ss;
    const char* reg_names[] = {
        "rdi",
        "rsi",
        "rbp",
        "rsp",
        "rbx",
        "rdx",
        "rcx",
        "rax",
        "r8",
        "r9",
        "r10",
        "r11",
        "r12",
        "r13",
        "r14",
        "r15",
    };
    const REG regs[] =
    {
        REG_GDI,
        REG_GSI,
        REG_GBP,
        REG_STACK_PTR,
        REG_GBX,
        REG_GDX,
        REG_GCX,
        REG_GAX,
        REG_R8,
        REG_R9,
        REG_R10,
        REG_R11,
        REG_R12,
        REG_R13,
        REG_R14,
        REG_R15
    };
    const size_t regsCount = sizeof(regs) / sizeof(regs[0]);
    static ADDRINT values[regsCount] = { 0 };
    static ADDRINT spVal = 0;

    static bool wasLastMul = false;
    static ADDRINT trackedMulRes = 0;
    static ADDRINT trackedRes = 0;
    static bool hasTrackedRes = false;
    static REG trackedReg = REG_STACK_PTR;
    static ADDRINT changedTracked = 0;
    static size_t mulCntr = 0;


    ADDRINT Address = getReturnFromTheStack(ctx);
    if (Address != spVal) {
        ss << "[rsp] -> " << std::hex << Address << "; ";
        spVal = Address;
    }
    bool anyChanged = false;
    bool _hasTrackedRes = false;
    REG changedReg = REG_STACK_PTR; //last changed
    for (size_t i = 0; i < regsCount; i++) {
        REG reg = regs[i];
        const ADDRINT Address = (ADDRINT)PIN_GetContextReg(ctx, reg);
        if (values[i] == Address) continue;
        anyChanged = true;
        if (trackedRes && Address == trackedRes) {
            _hasTrackedRes = true;
            trackedReg = reg;
        }
        values[i] = Address;
        changedReg = reg;
        ss << reg_names[i] << " = " << std::hex << Address << " ";
    }
    if (_hasTrackedRes != hasTrackedRes) {

        if (_hasTrackedRes) {
            ss << " TRACKED_CHANGED ";
            ss << "BY: " << disasm;
            std::stringstream s1;
            s1 << std::hex;
            if (disasm.find("sub") != std::string::npos) s1 << "res -= m";
            if (disasm.find("add") != std::string::npos) s1 << "res += m";
            if (disasm.find("xor") != std::string::npos) s1 << "res ^= m";
            ss << " #[ " << s1.str() << " ] ";
            traceLog.logListingLine(s1.str());
            changedTracked = 0;
        }
        else {
            changedTracked = (ADDRINT)PIN_GetContextReg(ctx, trackedReg);
            ss << " TRACKED_CHANGED ";
            ss << " -> VAL: " << changedTracked;
        }
    }
    hasTrackedRes = _hasTrackedRes;

    if (wasLastMul) {
        trackedMulRes = (ADDRINT)PIN_GetContextReg(ctx, REG_GAX);
        ss << " !!! MUL_RES: " << std::hex << trackedMulRes;
        wasLastMul = false;
    }
    static bool isPrevArithm = false;
    bool arithm = false;
    if (disasm.find("sub ") == 0 ||
        disasm.find("add ") == 0 ||
        disasm.find("xor ") == 0 ||
        disasm.find("or ") == 0 ||
        disasm.find("and ") == 0
        )
    {
        arithm = true;
    }
    bool isArithmTrackingEnabled = (mulCntr == 7) ? true : false;
    if (isArithmTrackingEnabled && arithm) {
        ss << " TRACKED_ARITHM: " << disasm;
    }
    if (isArithmTrackingEnabled && isPrevArithm && anyChanged) {
        ss << " TRACKED_ARITHM_RES ";
    }
    isPrevArithm = arithm;
    if (disasm.find("test ") != std::string::npos) {
        ss << " TRACKED_TEST ";
        for (size_t i = 0; i < regsCount; i++) {
            if (disasm.find(reg_names[i]) != std::string::npos) {
                REG reg = regs[i];
                const ADDRINT Address = (ADDRINT)PIN_GetContextReg(ctx, reg);
                ss << reg_names[i] << " = " << std::hex << Address;
                printDifference(ss, changedTracked, Address);
                changedTracked = Address;
                mulCntr = 0;
                traceLog.logListingLine("\n###\n");
            }
        }
    }

    if (disasm.find("mul ") != std::string::npos) {
        const ADDRINT rax = (ADDRINT)PIN_GetContextReg(ctx, REG_GAX);
        ADDRINT changed = 0;
        if (changedReg != REG_STACK_PTR) {
            mulCntr++;
            changed = (ADDRINT)PIN_GetContextReg(ctx, changedReg);
        }
        bool showDiff = true;
        ADDRINT m = rax * spVal;

        ss << " !!! TRACKED_MULTIPLYING: ";

        std::stringstream s1;
        s1 << std::hex;

        if (mulCntr == 0)
            s1 << "res";
        else
            s1 << "m";

        s1 << " = ";

        if (g_Test) {
            int indx = getValIndx(rax);
            s1 << "x_" << std::dec << indx << " ";
        }
        else {
            s1 << std::hex << rax;
        }

        s1 << std::hex << " * 0x" << spVal;
        traceLog.logListingLine(s1.str());
        ss << "#[ " << s1.str() << " ] ";
        //ss << " = " << std::hex << m;

        if (showDiff && mulCntr > 1) {
            printDifference(ss, changedTracked, changed);
        }
        trackedRes = changed;
        wasLastMul = true;

        if (mulCntr == 1) {
            std::stringstream s1;
            s1 << std::hex;
            s1 << "#[ ";
            printArithm(s1, trackedMulRes, changed);
            s1 << " ]";
            traceLog.logListingLine(s1.str());

            ss << " " << s1.str();
        }
        ss << "// [CNTR: " << mulCntr << "] ";
    }

    std::string out = ss.str();
    if (out.length()) {
        return "{ " + out + " }";
    }
    return "";
}

VOID LogInstruction(const CONTEXT* ctxt, std::string* disasmStr)
{
    if (!disasmStr) return;

    const char* disasm = disasmStr->c_str();
    if (!disasm) return;

    PinLocker locker;

    const ADDRINT Address = (ADDRINT)PIN_GetContextReg(ctxt, REG_INST_PTR);

    const ADDRINT base = get_mod_base(Address);
    if (base == UNKNOWN_ADDR) {
        return;
    }
    const ADDRINT rva = Address - base;
    if (rva < g_disasmStart || rva > g_disasmStop) {
        return;
    }

    if (base != UNKNOWN_ADDR && rva != UNKNOWN_ADDR) {
        std::stringstream ss;
        ss << disasm;
        traceLog.logLine("\t\t\t\t" + dumpContext(disasm, ctxt));
        traceLog.logInstruction(base, rva, ss.str());
    }
}



/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

VOID InstrumentInstruction(INS ins, VOID* v)
{
    const IMG pImg = IMG_FindByAddress(INS_Address(ins));
    BOOL inWatchedModule = FALSE;
    if (!IMG_Valid(pImg) || IMG_IsMainExecutable(pImg))
    {
        inWatchedModule = TRUE;
    }
    // only the main module:
    if (inWatchedModule && g_disasmStart) {

        INS_InsertCall(
            ins,
            IPOINT_BEFORE, (AFUNPTR)LogInstruction,
            IARG_CONTEXT,
            IARG_PTR, new std::string(INS_Disassemble(ins)),
            IARG_END
        );

    }
}


VOID Fini(INT32 code, VOID* v)
{
    std::cout << "Done" << endl;
}

/*!
 * The main procedure of the tool.
 * This function is called when the application image is loaded but not yet started.
 * @param[in]   argc            total number of elements in the argv array
 * @param[in]   argv            array of command line arguments, 
 *                              including pin -t <toolname> -- ...
 */
int main(int argc, char* argv[])
{
    // Initialize PIN library. Print help message if -h(elp) is specified
    // in the command line or the command line is invalid
    if (PIN_Init(argc, argv))
    {
        return Usage();
    }

    std::string app_name;
    // init App Name:
    for (int i = 1; i < (argc - 1); i++) {
        if (strcmp(argv[i], "--") == 0) {
            app_name = argv[i + 1];
            break;
        }
    }
    g_Test = KnobCheck;
    if (g_Test) {
        std::cerr << "Test mode enabled\n";
    }
    
    traceLog.init(app_name);

    // Register function to be called before every instruction
    INS_AddInstrumentFunction(InstrumentInstruction, NULL);


    // Register function to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);


    cerr << "===============================================" << endl;
    cerr << "This application is instrumented by MyPinTool" << endl;
    cerr << "===============================================" << endl;

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
