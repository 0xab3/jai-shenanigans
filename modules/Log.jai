log_debug :: (format_string: string, args: .. Any, loc := #caller_location, flags := Log_Flags.VERBOSE_ONLY, user_flags : u32 = 0, section : *Log_Section = null) {
    log(format_string, ..args, loc, flags, user_flags, section);
} @PrintLike
log_err  :: log_error;
log_info :: log;
log_warn :: log;

#scope_file
#import "Basic";
