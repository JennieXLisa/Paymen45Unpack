#pragma once

#include "Unpacker.hpp"

int __stdcall IDAP_init() {
    if (inf.filetype != f_PE) {
        warning("Only Microsoft PE File is Support\n");
        return PLUGIN_SKIP;
    }
    return PLUGIN_OK;
}

void term() {

}

void get_xrefs(ea_t ea, ea_t* call_addr) {
    xrefblk_t xref;
    uint8 i = 0;
    
    insn_t ins;
    ea_t track_ea = ea;
    func_t *f = get_func(ea);

    qstring str_ins;

    do {
        generate_disasm_line(&str_ins, track_ea);
        tag_remove(&str_ins,str_ins.c_str());
        decode_insn(&ins, track_ea);

        if (!strncmp(str_ins.c_str(),"call",4) || !strncmp(str_ins.c_str(),"jmp",3))
        {
            if (xref.first_from(track_ea, XREF_FAR)) {

                call_addr[i] = xref.to;
                i++;
            }
        }
        track_ea += ins.size;
    } while (track_ea < f->end_ea);
    
}

ea_t find_ins(func_t* f,const char* s_ins, ea_t ea = 0) {
    bool setbp = false;
    ea_t track_ea;
    qstring str_ins;
    insn_t ins;

    if (ea)
    {
        track_ea = ea;
    }
    else {
        track_ea = f->start_ea;
    }

    do
    {
        generate_disasm_line(&str_ins, track_ea);
        tag_remove(&str_ins, str_ins.c_str());
        decode_insn(&ins, track_ea);
        if (!strncmp(str_ins.c_str(), s_ins, strlen(s_ins)))
        {
            return track_ea;
        }
        track_ea += ins.size;
    } while (track_ea < f->end_ea);
}

void find_oep(ea_t eax) {

    ea_t* tf_1 = new ea_t[2]();
    get_xrefs(eax,tf_1);
    msg("tf_1 %llX\n",tf_1[0]);
    add_func(tf_1[0]);


    
    
    ea_t* tf_2 = new ea_t[2]();
    get_xrefs(tf_1[0], tf_2);
    msg("tf_2 %llX\n", tf_2[1]);
    add_func(tf_2[1]);
    
   
    ea_t* tf_3 = new ea_t[1];
    get_xrefs(tf_2[1], tf_3);
    msg("tf_3 %llX\n", tf_3[0]);
    add_func(tf_3[0]);

    func_t* f = get_func(tf_3[0]);
    ea_t ea = find_ins(f, "jmp");
    msg("JMP ADDR %llX", ea);
    

    request_run_to(ea);

    request_step_into();
    request_step_into();
    run_requests();

    wait_for_next_event(WFNE_SUSP, -1);


    
    uint64 eip;

    get_reg_val("EIP", &eip);
    create_insn(eip);
    request_run_to(eip+46);
    request_step_into();
    run_requests();

    wait_for_next_event(WFNE_SUSP, -1);
    
    
    
    get_reg_val("EIP", &eip);
    if (add_func(eip)) {
        f = get_func(eip);
        ea = find_ins(f, "leave");
        ea = find_ins(f, "leave", ea + 2);

        request_run_to(ea);
        request_step_into();
        request_step_into();
        run_requests();

        wait_for_next_event(WFNE_SUSP, -1);
    }
    
    // Here We are at OEP

    
}

bool __stdcall IDAP_run(size_t arg) {
    // Before Debugging Start We need To Find The MainFunction

    qstring fname;
    func_t main;
    for (func_t* f = get_next_func(0); f != NULL; f = get_next_func(f->start_ea)) {
        get_func_name(&fname, f->start_ea);
        if (!strncmp(fname.c_str(), "_WinMain", 7)) {
            msg("Main Function Found At Address %llx\n", f->start_ea);
            main = *f;
            break;
        }
    }


    // After Getting Main Function Addr We need to search call eax

    qstring ins;
    insn_t out;
    ea_t track_ea = main.start_ea;
    bool status = false;
    do {
        generate_disasm_line(&ins, track_ea);
        decode_insn(&out, track_ea);
        tag_remove(&ins, ins);
        if (!qstrcmp(ins.c_str(), "call    eax")) {
            add_bpt(track_ea, 0, BPT_SOFT);
            msg("Set Software BreakPoint At %llX\n", track_ea);
            status = true;
            break;
        }
        track_ea += out.size;
    } while (track_ea < main.end_ea);

    // Check if we successfully set the breakpoint

    if (!status) {
        msg("Cannont Find The Call To Second Stage\n");
        return 0;
    }



    // Run The Program Tail The Breakpoint

    add_bpt(main.start_ea, 0, BPT_SOFT);
    request_run_to(main.start_ea);
    request_run_to(track_ea);
    run_requests();

    
    uint64 eax;
    wait_for_next_event(WFNE_SUSP, -1);
    get_reg_val("EAX",&eax);
    msg("Finding OEP via EAX Value %X\n",eax);
    // First We Need To Create instruction first 

    create_insn(eax, NULL);
    add_func(eax);

    find_oep(eax);


    return 1;
}




char IDAP_COMMENT[] = "OEP finder For Paymen45 Ransomware";
char IDAP_HELP[] = "";
char IDAP_NAME[] = "Find OEP of Paymen45";
char IDAP_HOTKEY[] = "Alt+U";

plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    0,
    IDAP_init,
    NULL,
    IDAP_run,
    IDAP_COMMENT,
    IDAP_HELP,
    IDAP_NAME,
    IDAP_HOTKEY
};
