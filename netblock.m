// NetBlock.m - blocks network activity inside a LiveContainer guest app
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <Network/Network.h>
#import <sys/socket.h>
#import <netdb.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <errno.h>
#import "fishhook.h"

// Set to 1 if the app needs localhost (local servers, debug bridges, etc.)
#define ALLOW_LOOPBACK 0

#pragma mark - Helpers

static BOOL isLoopbackAddr(const struct sockaddr *sa) {
    if (!sa) return NO;
    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in *s = (const void *)sa;
        return (ntohl(s->sin_addr.s_addr) >> 24) == 127;
    }
    if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *s = (const void *)sa;
        return IN6_IS_ADDR_LOOPBACK(&s->sin6_addr);
    }
    return NO;
}

static BOOL shouldBlockAddr(const struct sockaddr *sa) {
    if (!sa) return NO;
    if (sa->sa_family != AF_INET && sa->sa_family != AF_INET6) return NO; // allow AF_UNIX etc.
#if ALLOW_LOOPBACK
    if (isLoopbackAddr(sa)) return NO;
#endif
    return YES;
}

static BOOL isLocalHostName(const char *h) {
#if ALLOW_LOOPBACK
    return h && (!strcmp(h, "localhost") || !strcmp(h, "127.0.0.1") || !strcmp(h, "::1"));
#else
    return NO;
#endif
}

#pragma mark - C-level hooks

static int (*orig_socket)(int, int, int);
static int (*orig_connect)(int, const struct sockaddr *, socklen_t);
static int (*orig_connectx)(int, const sa_endpoints_t *, sae_associd_t, unsigned int,
                            const struct iovec *, unsigned int, size_t *, sae_connid_t *);
static ssize_t (*orig_sendto)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
static ssize_t (*orig_sendmsg)(int, const struct msghdr *, int);
static int (*orig_getaddrinfo)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
static struct hostent *(*orig_gethostbyname)(const char *);
static void (*orig_nw_connection_start)(nw_connection_t);

static int my_socket(int domain, int type, int proto) {
#if !ALLOW_LOOPBACK
    if (domain == AF_INET || domain == AF_INET6) { errno = ENETDOWN; return -1; }
#endif
    return orig_socket(domain, type, proto);
}

static int my_connect(int fd, const struct sockaddr *sa, socklen_t len) {
    if (shouldBlockAddr(sa)) { errno = ENETUNREACH; return -1; }
    return orig_connect(fd, sa, len);
}

static int my_connectx(int fd, const sa_endpoints_t *ep, sae_associd_t aid, unsigned int flags,
                       const struct iovec *iov, unsigned int iovcnt, size_t *len, sae_connid_t *cid) {
    if (ep && shouldBlockAddr(ep->sae_dstaddr)) { errno = ENETUNREACH; return -1; }
    return orig_connectx(fd, ep, aid, flags, iov, iovcnt, len, cid);
}

static ssize_t my_sendto(int fd, const void *buf, size_t n, int flags,
                         const struct sockaddr *to, socklen_t tolen) {
    if (shouldBlockAddr(to)) { errno = ENETUNREACH; return -1; }
    return orig_sendto(fd, buf, n, flags, to, tolen);
}

static ssize_t my_sendmsg(int fd, const struct msghdr *msg, int flags) {
    if (msg && shouldBlockAddr((const struct sockaddr *)msg->msg_name)) { errno = ENETUNREACH; return -1; }
    return orig_sendmsg(fd, msg, flags);
}

static int my_getaddrinfo(const char *host, const char *svc,
                          const struct addrinfo *hints, struct addrinfo **res) {
    if (host && !isLocalHostName(host)) {
        if (res) *res = NULL;
        return EAI_FAIL;
    }
    return orig_getaddrinfo(host, svc, hints, res);
}

static struct hostent *my_gethostbyname(const char *name) {
    if (!isLocalHostName(name)) { h_errno = HOST_NOT_FOUND; return NULL; }
    return orig_gethostbyname(name);
}

static void my_nw_connection_start(nw_connection_t c) {
    nw_connection_cancel(c);   // never starts; state handler sees "cancelled"
}

#pragma mark - NSURLProtocol blocker

@interface NBBlockProtocol : NSURLProtocol
@end

@implementation NBBlockProtocol
+ (BOOL)canInitWithRequest:(NSURLRequest *)r {
    NSString *s = r.URL.scheme.lowercaseString;
    if (![s isEqualToString:@"http"] && ![s isEqualToString:@"https"]) return NO;
#if ALLOW_LOOPBACK
    NSString *h = r.URL.host.lowercaseString;
    if ([h isEqualToString:@"localhost"] || [h isEqualToString:@"127.0.0.1"] || [h isEqualToString:@"::1"]) return NO;
#endif
    return YES;
}
+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)r { return r; }
- (void)startLoading {
    NSError *e = [NSError errorWithDomain:NSURLErrorDomain
                                     code:NSURLErrorNotConnectedToInternet
                                 userInfo:@{NSLocalizedDescriptionKey: @"The Internet connection appears to be offline."}];
    [self.client URLProtocol:self didFailWithError:e];
}
- (void)stopLoading {}
@end

// Inject our protocol into every NSURLSessionConfiguration
static NSArray *(*orig_protocolClasses)(id, SEL);
static NSArray *my_protocolClasses(id self, SEL _cmd) {
    NSArray *orig = orig_protocolClasses(self, _cmd) ?: @[];
    return [@[NBBlockProtocol.class] arrayByAddingObjectsFromArray:orig];
}

#pragma mark - Entry point

__attribute__((constructor))
static void NetBlockInit(void) {
    // Foundation layer
    [NSURLProtocol registerClass:NBBlockProtocol.class];
    Method m = class_getInstanceMethod(NSURLSessionConfiguration.class, @selector(protocolClasses));
    if (m) {
        orig_protocolClasses = (void *)method_getImplementation(m);
        method_setImplementation(m, (IMP)my_protocolClasses);
    }

    // C layer
    rebind_symbols((struct rebinding[]){
        {"socket",              my_socket,              (void *)&orig_socket},
        {"connect",             my_connect,             (void *)&orig_connect},
        {"connectx",            my_connectx,            (void *)&orig_connectx},
        {"sendto",              my_sendto,              (void *)&orig_sendto},
        {"sendmsg",             my_sendmsg,             (void *)&orig_sendmsg},
        {"getaddrinfo",         my_getaddrinfo,         (void *)&orig_getaddrinfo},
        {"gethostbyname",       my_gethostbyname,       (void *)&orig_gethostbyname},
        {"nw_connection_start", my_nw_connection_start, (void *)&orig_nw_connection_start},
    }, 8);

    NSLog(@"[NetBlock] network blocking active");
}