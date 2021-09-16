LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := MemoryInspector

LOCAL_SRC_FILES :=	main.cpp

LOCAL_C_INCLUDES :=

LOCAL_CFLAGS :=	\
	-Wall	\
	-std=gnu++14

LOCAL_CPP_FEATURES += exceptions
LOCAL_CPPFLAGS += -fexceptions

include $(BUILD_EXECUTABLE)
