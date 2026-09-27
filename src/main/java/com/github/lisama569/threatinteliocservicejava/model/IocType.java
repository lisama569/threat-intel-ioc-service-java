package com.github.lisama569.threatinteliocservicejava.model;

/** IOC 类型。URL 与单地址 CIDR 会在归一化阶段折叠为 DOMAIN/IP。 */
public enum IocType {
    DOMAIN,
    IP,
    CIDR,
    HASH
}
