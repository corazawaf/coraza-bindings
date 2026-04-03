/*
 * jni_register.c
 *
 * Registers the SWIG-generated callback native methods with their correct
 * fully-qualified Java class name.
 *
 * When SWIG generates native method declarations via %pragma(java) modulecode,
 * the corresponding C functions are named Java_<module>_<method> (e.g.
 * Java_coraza_coraza_1set_1error_1callback).  However, once a -package flag is
 * passed to SWIG, the Java class lives under that package, so the JVM resolves
 * the native symbol as Java_<pkg>_<module>_<method>.  These two names differ,
 * causing UnsatisfiedLinkError.
 *
 * JNI_OnLoad (called when System.loadLibrary loads the .so/.dylib) uses
 * RegisterNatives to bind the two methods to the correct class.
 */

#include <jni.h>
#include <stdlib.h>
#include <string.h>

/* Forward-declare the SWIG-generated C implementations. */
JNIEXPORT jint JNICALL Java_coraza_coraza_1set_1error_1callback(
    JNIEnv *env, jclass cls, jlong cfg, jobject callback);

JNIEXPORT jint JNICALL Java_coraza_coraza_1set_1debug_1log_1callback(
    JNIEnv *env, jclass cls, jlong cfg, jobject callback);

static JNINativeMethod gCallbackMethods[] = {
    {
        (char *)"coraza_set_error_callback",
        (char *)"(JLjava/lang/Object;)I",
        (void *)Java_coraza_coraza_1set_1error_1callback
    },
    {
        (char *)"coraza_set_debug_log_callback",
        (char *)"(JLjava/lang/Object;)I",
        (void *)Java_coraza_coraza_1set_1debug_1log_1callback
    },
};

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env = NULL;
    (void)reserved;

    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_8) != JNI_OK) {
        return JNI_ERR;
    }

    jclass cls = (*env)->FindClass(
        env,
        "org/corazawaf/coraza/internal/swig/coraza");
    if (cls == NULL) {
        /* Class not found — package may differ; clear the pending exception. */
        (*env)->ExceptionClear(env);
        return JNI_VERSION_1_8;
    }

    (*env)->RegisterNatives(env, cls, gCallbackMethods,
                            sizeof(gCallbackMethods) / sizeof(gCallbackMethods[0]));
    /* Ignore registration errors — the unregistered methods will produce
     * UnsatisfiedLinkError only if actually called. */
    (*env)->ExceptionClear(env);

    return JNI_VERSION_1_8;
}
