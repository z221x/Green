/* No-op stubs for the optional gum heap-profiler API referenced by the
 * gumjs runtime.  Green does not expose the profiler to scripts. */
#include <glib.h>
#include <gum/gumprofiler.h>
#include <gum/gumsampler.h>

GumInstrumentReturn
gum_profiler_instrument_function_with_inspector (GumProfiler * self,
    gpointer function_address, GumSampler * sampler,
    GumWorstCaseInspectorFunc inspector_func, gpointer data,
    GDestroyNotify data_destroy)
{
  return GUM_INSTRUMENT_SUCCESS;
}

GumInstrumentReturn
gum_profiler_instrument_function (GumProfiler * self,
    gpointer function_address, GumSampler * sampler)
{
  return GUM_INSTRUMENT_SUCCESS;
}

GumProfiler * gum_profiler_new (void) { return NULL; }
void gum_profiler_instrument_functions_matching (GumProfiler * self,
    const gchar * match_str, GumSampler * sampler)
{ (void) self; (void) match_str; (void) sampler; }
GumProfileReport * gum_profiler_generate_report (GumProfiler * self)
{ (void) self; return NULL; }
guint gum_profiler_get_number_of_threads (GumProfiler * self)
{ (void) self; return 0; }
guint64 gum_profiler_get_total_duration_of (GumProfiler * self,
    gpointer function_address)
{ (void) self; (void) function_address; return 0; }
guint64 gum_profiler_get_worst_case_duration_of (GumProfiler * self,
    gpointer function_address)
{ (void) self; (void) function_address; return 0; }
const gchar * gum_profiler_get_worst_case_info_of (GumProfiler * self,
    gpointer function_address)
{ (void) self; (void) function_address; return NULL; }

gchar * gum_profile_report_emit_xml (GumProfileReport * self)
{ (void) self; return g_strdup ("<?xml version=\"1.0\"?><profile/>"); }

/* ---- sampler family (never called: profiler not exposed to scripts) --- */
gpointer gum_busy_cycle_sampler_new (void) { return NULL; }
gpointer gum_busy_cycle_sampler_new_with_defaults (void) { return NULL; }
guint gum_busy_cycle_sampler_get_type (void) { return 0; }
gboolean gum_busy_cycle_sampler_is_available (void) { return FALSE; }
gpointer gum_call_count_sampler_newv (gchar ** functions) { (void) functions; return NULL; }
guint gum_cycle_sampler_get_type (void) { return 0; }
gpointer gum_cycle_sampler_new (void) { return NULL; }
gpointer gum_cycle_sampler_new_with_defaults (void) { return NULL; }
gboolean gum_cycle_sampler_is_available (void) { return FALSE; }
gpointer gum_malloc_count_sampler_new_with_heap_apis (
    GumHeapApiList * apis) { (void) apis; return NULL; }
guint gum_sampler_sample (GumSampler * self) { (void) self; return 1; }
guint gum_user_time_sampler_get_type (void) { return 0; }
gpointer gum_user_time_sampler_new_with_thread_id (
    gulong thread_id) { (void) thread_id; return NULL; }
gboolean gum_user_time_sampler_is_available (void) { return FALSE; }
guint gum_wall_clock_sampler_get_type (void) { return 0; }
gpointer gum_wall_clock_sampler_new (void) { return NULL; }
gpointer gum_wall_clock_sampler_new_with_default_period (void) { return NULL; }

/* ---- compression stubs (libdwarf/gum optional paths) ---- */
void inflate (void); void inflate (void) {}
void inflateEnd (void); void inflateEnd (void) {}
void inflateGetHeader (void); void inflateGetHeader (void) {}
void inflateInit_ (void); void inflateInit_ (void) {}
void inflateInit2_ (void); void inflateInit2_ (void) {}
void inflateReset (void); void inflateReset (void) {}
void lzma_index_buffer_decode (void); void lzma_index_buffer_decode (void) {}
void lzma_index_end (void); void lzma_index_end (void) {}
void lzma_index_size (void); void lzma_index_size (void) {}
void lzma_index_uncompressed_size (void); void lzma_index_uncompressed_size (void) {}
void lzma_stream_buffer_decode (void); void lzma_stream_buffer_decode (void) {}
void lzma_stream_footer_decode (void); void lzma_stream_footer_decode (void) {}
void uncompress (void); void uncompress (void) {}
void ZSTD_decompress (void) {}
