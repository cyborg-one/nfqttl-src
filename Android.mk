LOCAL_PATH:=$(call my-dir)


#####################################################################
#                     build libnetlink                              #
#####################################################################
include $(CLEAR_VARS)
LOCAL_MODULE:=libnetlink
LOCAL_C_INCLUDES:=$(LOCAL_PATH)/lib/libnetlink/include \
    $(LOCAL_PATH)/lib/libnetlink/include/uapi \
    $(LOCAL_PATH)/lib/libmnl/include
LOCAL_SRC_FILES:=$(LOCAL_PATH)/lib/libnetlink/libnetlink.c
LOCAL_CFLAGS += -DHAVE_LIBMNL
include $(BUILD_STATIC_LIBRARY)


#####################################################################
#                     build libnfnetlink                            #
#####################################################################
include $(CLEAR_VARS)
LOCAL_MODULE:=libnfnetlink
LOCAL_C_INCLUDES:= $(LOCAL_PATH)/lib/libnfnetlink/include
LOCAL_SRC_FILES:=$(LOCAL_PATH)/lib/libnfnetlink/src/iftable.c \
    $(LOCAL_PATH)/lib/libnfnetlink/src/rtnl.c \
    $(LOCAL_PATH)/lib/libnfnetlink/src/libnfnetlink.c
include $(BUILD_STATIC_LIBRARY)


#####################################################################
#                        build libmnl                               #
#####################################################################

include $(CLEAR_VARS)
LOCAL_C_INCLUDES:=$(LOCAL_PATH)/lib/libmnl/include \
    $(LOCAL_PATH)/lib/libmnl
LOCAL_MODULE:=libmnl
LOCAL_SRC_FILES:=$(LOCAL_PATH)/lib/libmnl/src/attr.c \
    $(LOCAL_PATH)/lib/libmnl/src/socket.c \
    $(LOCAL_PATH)/lib/libmnl/src/nlmsg.c \
    $(LOCAL_PATH)/lib/libmnl/src/callback.c
include $(BUILD_STATIC_LIBRARY)

#####################################################################
#                   build libnetfilter_queue                        #
#####################################################################


include $(CLEAR_VARS)
LOCAL_C_INCLUDES :=$(LOCAL_PATH)/lib/libnetfilter_queue/include \
    $(LOCAL_PATH)/lib/libnetfilter_queue \
    $(LOCAL_PATH)/lib/libnetfilter_queue/src \
    $(LOCAL_PATH)/lib/libnfnetlink/include \
    $(LOCAL_PATH)/lib/libmnl/include
LOCAL_MODULE:=netfilter_queue
LOCAL_SRC_FILES:=$(LOCAL_PATH)/lib/libnetfilter_queue/src/libnetfilter_queue.c \
    $(LOCAL_PATH)/lib/libnetfilter_queue/src/extra/ipv4.c \
    $(LOCAL_PATH)/lib/libnetfilter_queue/src/extra/ipv6.c \
    $(LOCAL_PATH)/lib/libnetfilter_queue/src/extra/tcp.c \
    $(LOCAL_PATH)/lib/libnetfilter_queue/src/extra/pktbuff.c \
    $(LOCAL_PATH)/lib/libnetfilter_queue/src/extra/checksum.c \
    $(LOCAL_PATH)/lib/libnetfilter_queue/src/nlmsg.c
LOCAL_STATIC_LIBRARIES:=libnfnetlink libmnl

LOCAL_CFLAGS += -D_UAPI_LINUX_TCP_H -D__USE_BSD -D_UAPI_NFNETLINK_H
include $(BUILD_STATIC_LIBRARY)


#####################################################################
#                     build nfqttl                                  #
#####################################################################


include $(CLEAR_VARS)
LOCAL_C_INCLUDES := $(LOCAL_PATH)/lib/libnetfilter_queue/include \
    $(LOCAL_PATH)/lib/libnetfilter_queue \
    $(LOCAL_PATH)/lib/libmnl/include \
    $(LOCAL_PATH)/lib/libnfnetlink/include \
    $(LOCAL_PATH)/lib/libnetlink/include \
    $(LOCAL_PATH)/include
LOCAL_MODULE:=nfqttl
LOCAL_SRC_FILES:= $(LOCAL_PATH)/nfqttl.c
LOCAL_STATIC_LIBRARIES:=libmnl libnetfilter_queue libnetlink
LOCAL_LDFLAGS += -O3
include $(BUILD_EXECUTABLE)
