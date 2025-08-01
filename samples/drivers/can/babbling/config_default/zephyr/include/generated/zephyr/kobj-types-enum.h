/* Core kernel objects */
K_OBJ_MEM_SLAB,
K_OBJ_MSGQ,
K_OBJ_MUTEX,
K_OBJ_PIPE,
K_OBJ_QUEUE,
K_OBJ_POLL_SIGNAL,
K_OBJ_SEM,
K_OBJ_STACK,
K_OBJ_THREAD,
K_OBJ_TIMER,
K_OBJ_THREAD_STACK_ELEMENT,
K_OBJ_NET_SOCKET,
K_OBJ_NET_IF,
K_OBJ_SYS_MUTEX,
K_OBJ_FUTEX,
K_OBJ_CONDVAR,
#ifdef CONFIG_EVENTS
K_OBJ_EVENT,
#endif
#ifdef CONFIG_ZTEST
K_OBJ_ZTEST_SUITE_NODE,
#endif
#ifdef CONFIG_ZTEST
K_OBJ_ZTEST_SUITE_STATS,
#endif
#ifdef CONFIG_ZTEST
K_OBJ_ZTEST_UNIT_TEST,
#endif
#ifdef CONFIG_ZTEST
K_OBJ_ZTEST_TEST_RULE,
#endif
#ifdef CONFIG_RTIO
K_OBJ_RTIO,
#endif
#ifdef CONFIG_RTIO
K_OBJ_RTIO_IODEV,
#endif
#ifdef CONFIG_SENSOR_ASYNC_API
K_OBJ_SENSOR_DECODER_API,
#endif
/* Driver subsystems */
K_OBJ_DRIVER_CAN,
K_OBJ_DRIVER_GPIO,
K_OBJ_DRIVER_RESET,
K_OBJ_DRIVER_SHARED_IRQ,
K_OBJ_DRIVER_CRYPTO,
K_OBJ_DRIVER_ADC,
K_OBJ_DRIVER_AUXDISPLAY,
K_OBJ_DRIVER_BBRAM,
K_OBJ_DRIVER_BT_HCI,
K_OBJ_DRIVER_CELLULAR,
K_OBJ_DRIVER_CHARGER,
K_OBJ_DRIVER_CLOCK_CONTROL,
K_OBJ_DRIVER_COMPARATOR,
K_OBJ_DRIVER_COREDUMP,
K_OBJ_DRIVER_COUNTER,
K_OBJ_DRIVER_DAC,
K_OBJ_DRIVER_DAI,
K_OBJ_DRIVER_DISPLAY,
K_OBJ_DRIVER_DMA,
K_OBJ_DRIVER_EDAC,
K_OBJ_DRIVER_EEPROM,
K_OBJ_DRIVER_EMUL_BBRAM,
K_OBJ_DRIVER_FUEL_GAUGE_EMUL,
K_OBJ_DRIVER_EMUL_SENSOR,
K_OBJ_DRIVER_ENTROPY,
K_OBJ_DRIVER_ESPI,
K_OBJ_DRIVER_ESPI_SAF,
K_OBJ_DRIVER_FLASH,
K_OBJ_DRIVER_FPGA,
K_OBJ_DRIVER_FUEL_GAUGE,
K_OBJ_DRIVER_GNSS,
K_OBJ_DRIVER_HAPTICS,
K_OBJ_DRIVER_HWSPINLOCK,
K_OBJ_DRIVER_I2C,
K_OBJ_DRIVER_I2C_TARGET,
K_OBJ_DRIVER_I2S,
K_OBJ_DRIVER_I3C,
K_OBJ_DRIVER_IPM,
K_OBJ_DRIVER_LED,
K_OBJ_DRIVER_LED_STRIP,
K_OBJ_DRIVER_LORA,
K_OBJ_DRIVER_MBOX,
K_OBJ_DRIVER_MDIO,
K_OBJ_DRIVER_MIPI_DBI,
K_OBJ_DRIVER_MIPI_DSI,
K_OBJ_DRIVER_MSPI,
K_OBJ_DRIVER_PECI,
K_OBJ_DRIVER_PS2,
K_OBJ_DRIVER_PTP_CLOCK,
K_OBJ_DRIVER_PWM,
K_OBJ_DRIVER_REGULATOR_PARENT,
K_OBJ_DRIVER_REGULATOR,
K_OBJ_DRIVER_RETAINED_MEM,
K_OBJ_DRIVER_RTC,
K_OBJ_DRIVER_SDHC,
K_OBJ_DRIVER_SENSOR,
K_OBJ_DRIVER_SMBUS,
K_OBJ_DRIVER_SPI,
K_OBJ_DRIVER_STEPPER,
K_OBJ_DRIVER_SYSCON,
K_OBJ_DRIVER_TEE,
K_OBJ_DRIVER_VIDEO,
K_OBJ_DRIVER_W1,
K_OBJ_DRIVER_WDT,
K_OBJ_DRIVER_CAN_TRANSCEIVER,
K_OBJ_DRIVER_NRF_CLOCK_CONTROL,
K_OBJ_DRIVER_I3C_TARGET,
K_OBJ_DRIVER_ITS,
K_OBJ_DRIVER_VTD,
K_OBJ_DRIVER_TGPIO,
K_OBJ_DRIVER_PCIE_CTRL,
K_OBJ_DRIVER_PCIE_EP,
K_OBJ_DRIVER_SVC,
K_OBJ_DRIVER_UART,
K_OBJ_DRIVER_BC12_EMUL,
K_OBJ_DRIVER_BC12,
K_OBJ_DRIVER_USBC_PPC,
K_OBJ_DRIVER_TCPC,
K_OBJ_DRIVER_USBC_VBUS,
K_OBJ_DRIVER_IVSHMEM,
K_OBJ_DRIVER_ETHPHY,
