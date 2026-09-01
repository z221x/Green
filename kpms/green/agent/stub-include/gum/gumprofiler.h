/* Minimal stand-in for the gum heap profiler API (not exposed to scripts). */
#ifndef GREEN_STUB_GUMPROFILER_H
#define GREEN_STUB_GUMPROFILER_H
#include <glib.h>
typedef struct _GumProfiler GumProfiler;
typedef struct _GumSampler GumSampler;
typedef struct _GumInvocationContext GumInvocationContext;
typedef gpointer (*GumWorstCaseInspectorFunc) (GumInvocationContext * ctx,
    gpointer user_data);
typedef enum { GUM_INSTRUMENT_SUCCESS, GUM_INSTRUMENT_WRONG_SIGNATURE,
    GUM_INSTRUMENT_CANCELED } GumInstrumentReturn;
GumInstrumentReturn gum_profiler_instrument_function_with_inspector (GumProfiler * self,
    gpointer function_address, GumSampler * sampler,
    GumWorstCaseInspectorFunc inspector_func, gpointer data,
    GDestroyNotify data_destroy);
GumInstrumentReturn gum_profiler_instrument_function (GumProfiler * self,
    gpointer function_address, GumSampler * sampler);
typedef struct _GumProfileReport GumProfileReport;
GumProfileReport * gum_profiler_generate_report (GumProfiler * self);
guint gum_profiler_get_number_of_threads (GumProfiler * self);
guint64 gum_profiler_get_total_duration_of (GumProfiler * self,
    gpointer function_address);
guint64 gum_profiler_get_worst_case_duration_of (GumProfiler * self,
    gpointer function_address);
const gchar * gum_profiler_get_worst_case_info_of (GumProfiler * self,
    gpointer function_address);
#endif
