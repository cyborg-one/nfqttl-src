LOCAL_PATH:=$(call my-dir)

#####################################################################
#                     build libnflink                               #
#####################################################################
include $(CLEAR_VARS)
LOCAL_MODULE:=nflink
LOCAL_C_INCLUDES:= $(LOCAL_PATH)/libnfnetlink/include
LOCAL_SRC_FILES:=\
    $(LOCAL_PATH)/libnfnetlink/src/iftable.c \
    $(LOCAL_PATH)/libnfnetlink/src/rtnl.c \
    $(LOCAL_PATH)/libnfnetlink/src/libnfnetlink.c

include $(BUILD_STATIC_LIBRARY)

#####################################################################
#                   build libnetfilter_queue                        #
#####################################################################


include $(CLEAR_VARS)
LOCAL_C_INCLUDES := $(LOCAL_PATH)/libnfnetlink/include \
    $(LOCAL_PATH)/libnetfilter_queue/include \
    $(LOCAL_PATH)/libnetfilter_queue/include/libnetfilter_queue \
    $(LOCAL_PATH)/libnetfilter_queue/include/linux/netfilter \
    $(LOCAL_PATH)/libnetfilter_queue/src
LOCAL_MODULE:=netfilter_queue
LOCAL_SRC_FILES:=$(LOCAL_PATH)/libnetfilter_queue/src/extra/pktbuff.c \
    $(LOCAL_PATH)/libnetfilter_queue/src/extra/checksum.c \
    $(LOCAL_PATH)/libnetfilter_queue/src/extra/ipv4.c \
    $(LOCAL_PATH)/libnetfilter_queue/src/extra/ipv6.c \
    $(LOCAL_PATH)/libnetfilter_queue/src/libnetfilter_queue.c
LOCAL_STATIC_LIBRARIES:=libnflink
LOCAL_CFLAGS := -Wc,-nostartfiles -lnfnetlink
include $(BUILD_STATIC_LIBRARY)

#####################################################################
#                     build our code                                #
#####################################################################

include $(CLEAR_VARS)
LOCAL_C_INCLUDES := $(LOCAL_PATH)/libnfnetlink/include \
    $(LOCAL_PATH)/libnetfilter_queue/include
LOCAL_MODULE:=nfqttl
LOCAL_SRC_FILES:=$(LOCAL_PATH)/nfqttl.c
LOCAL_STATIC_LIBRARIES:=libnetfilter_queue
LOCAL_ALLOW_UNDEFINED_SYMBOLS := true
LOCAL_CFLAGS := -std=c11 -Wall -Wextra -g -ggdb
LOCAL_LDFLAGS += -fuse-ld=bfd
include $(BUILD_EXECUTABLE)
