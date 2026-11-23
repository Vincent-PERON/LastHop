"""OID numériques utilisés (aucune résolution de MIB à l'exécution)."""

SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"
ENT_PHYSICAL_MODEL_NAME_1 = "1.3.6.1.2.1.47.1.1.1.1.13.1"  # ENTITY-MIB, entPhysicalModelName.1
IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"

# --- Topologie (lot c)
IF_TYPE = "1.3.6.1.2.1.2.2.1.3"
IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"
DOT1D_BASE_BRIDGE_ADDRESS = "1.3.6.1.2.1.17.1.1.0"
DOT1D_BASE_PORT_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"
DOT1D_TP_FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"
DOT1D_TP_FDB_STATUS = "1.3.6.1.2.1.17.4.3.1.3"
DOT1Q_TP_FDB_PORT = "1.3.6.1.2.1.17.7.1.2.2.1.2"
DOT1Q_TP_FDB_STATUS = "1.3.6.1.2.1.17.7.1.2.2.1.3"
DOT1Q_VLAN_STATIC_EGRESS = "1.3.6.1.2.1.17.7.1.4.3.1.2"
DOT1Q_VLAN_STATIC_UNTAGGED = "1.3.6.1.2.1.17.7.1.4.3.1.4"
LLDP_LOC_CHASSIS_ID_SUBTYPE = "1.0.8802.1.1.2.1.3.1.0"
LLDP_LOC_CHASSIS_ID = "1.0.8802.1.1.2.1.3.2.0"
LLDP_LOC_PORT_ID_SUBTYPE = "1.0.8802.1.1.2.1.3.7.1.2"
LLDP_LOC_PORT_ID = "1.0.8802.1.1.2.1.3.7.1.3"
LLDP_REM = "1.0.8802.1.1.2.1.4.1.1"  # .col.timeMark.localPort.index
LLDP_REM_CHASSIS_SUBTYPE, LLDP_REM_CHASSIS_ID = 4, 5
LLDP_REM_PORT_SUBTYPE, LLDP_REM_PORT_ID, LLDP_REM_PORT_DESC = 6, 7, 8
LLDP_REM_SYS_NAME, LLDP_REM_SYS_DESC, LLDP_REM_SYS_CAP_ENABLED = 9, 10, 12
CDP_CACHE = "1.3.6.1.4.1.9.9.23.1.2.1.1"  # .col.ifIndex.deviceIndex
CDP_ADDRESS_TYPE, CDP_ADDRESS, CDP_DEVICE_ID, CDP_DEVICE_PORT, CDP_PLATFORM, CDP_CAPS = 3, 4, 6, 7, 8, 9
VTP_TRUNK_DYNAMIC_STATUS = "1.3.6.1.4.1.9.9.46.1.6.1.1.14"  # CISCO-VTP-MIB vlanTrunkPortDynamicStatus (1 = trunking)

# --- Learning (lot d)
IP_NET_TO_PHYSICAL_MAC = "1.3.6.1.2.1.4.35.1.4"  # ipNetToPhysicalPhysAddress  (idx: ifIndex.type.len.addr)
IP_NET_TO_PHYSICAL_STATE = "1.3.6.1.2.1.4.35.1.6"  # ipNetToPhysicalState
IP_NET_TO_MEDIA_MAC = "1.3.6.1.2.1.4.22.1.2"  # ipNetToMediaPhysAddress (idx: ifIndex.a.b.c.d)
IP_NET_TO_MEDIA_TYPE = "1.3.6.1.2.1.4.22.1.4"  # ipNetToMediaType : 3 = dynamic, 4 = static
VTP_VLAN_STATE = "1.3.6.1.4.1.9.9.46.1.3.1.1.2"  # idx: managementDomain.vlanIndex ; 1 = operational
VTP_VLAN_TYPE = "1.3.6.1.4.1.9.9.46.1.3.1.1.3"  # 1 = ethernet
