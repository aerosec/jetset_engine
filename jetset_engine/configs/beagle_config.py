from device.base_device import Simmio
import angr
import cle

target = 0x402024B8
arch = "arm"
arch_num = 1

ENTRY_POINT = 0x40200800

def get_project():
    '''
    One of the two functions that need to be implemented
    Does all the loading as well as arch specific config

    The beaglebone has a three-part boot sequence. We assume
    the x-loader binary, MLO, is mapped to memory address
    0x40014040. This is normally stored at the base of memory and
    then mapped to 0x40014040 by the ARM cortex A8.

    This MLO binary then searches for a U-BOOT.BIN file which
    is in the root directory of the OS; this second stage bootloader
    will unpack the kernel

    Seems like angr wants the binary at a bit of an offset, and
    not directly loaded at 0x40200800.

    Additionally, the entry point is a little strange. Loading the
    MLO binary directly, the first portion of it is a direct jump to
    a failure state which occurs after a probe of GPIO pin 5. So
    we skip over this section and go to what seems to be the actual
    entry point.
    '''

    MLO_path = "../jetset_public_data/beagle/kernel/MLO"
    boot_load_opts = {
        'backend': 'blob',
        'base_addr': 0x402007F8,
        'entry_point': ENTRY_POINT,
        'arch': 'ARM'
    }

    p = angr.Project(MLO_path,
                    load_options={'main_opts': boot_load_opts},
                    auto_load_libs=False)

       
    uboot_path = "../jetset_public_data/beagle/kernel/U-BOOT.BIN"
    data_backend = cle.backends.Blob(uboot_path,
                                        arch='ARM',
                                        base_addr=0x80000)
    p.loader.add_object(data_backend)
    return p



L3RT=Simmio(lower=0x68000000,
upper=0x680003FF,
name='L3RT')
L3SI=Simmio(lower=0x68000400,
upper=0x680007FF,
name='L3SI')
Reserved0=Simmio(lower=0x68000800,
upper=0x680013FF,
name='Reserved0')
MPUSSIA=Simmio(lower=0x68001400,
upper=0x680017FF,
name='MPUSSIA')
IVA22SSIA=Simmio(lower=0x68001800,
upper=0x68001BFF,
name='IVA22SSIA')
SGXSSIA=Simmio(lower=0x68001C00,
upper=0x68001FFF,
name='SGXSSIA')
SMSTA=Simmio(lower=0x68002000,
upper=0x680023FF,
name='SMSTA')
GPMCTA=Simmio(lower=0x68002400,
upper=0x680027FF,
name='GPMCTA')
OCMRAMTA=Simmio(lower=0x68002800,
upper=0x68002BFF,
name='OCMRAMTA')
OCMROMTA=Simmio(lower=0x68002C00,
upper=0x68002FFF,
name='OCMROMTA')
D2DIA=Simmio(lower=0x68003000,
upper=0x680033FF,
name='D2DIA')
D2DTA=Simmio(lower=0x68003400,
upper=0x680037FF,
name='D2DTA')
Reserved1=Simmio(lower=0x68003800,
upper=0x68003FFF,
name='Reserved1')
HSUSBHOSTIA=Simmio(lower=0x68004000,
upper=0x680043FF,
name='HSUSBHOSTIA')
HSUSBOTGIA=Simmio(lower=0x68004400,
upper=0x680047FF,
name='HSUSBOTGIA')
Reserved2=Simmio(lower=0x68004800,
upper=0x68004BFF,
name='Reserved2')
sDMARDIA=Simmio(lower=0x68004C00,
upper=0x68004FFF,
name='sDMARDIA')
sDMAWRIA=Simmio(lower=0x68005000,
upper=0x680053FF,
name='sDMAWRIA')
DisplaySSIA=Simmio(lower=0x68005400,
upper=0x680057FF,
name='DisplaySSIA')
CAMERAISPIA=Simmio(lower=0x68005800,
upper=0x68005BFF,
name='CAMERAISPIA')
DAPIA=Simmio(lower=0x68005C00,
upper=0x68005FFF,
name='DAPIA')
IVA22SSTA=Simmio(lower=0x68006000,
upper=0x680063FF,
name='IVA22SSTA')
SGXSSTA=Simmio(lower=0x68006400,
upper=0x680067FF,
name='SGXSSTA')
L4CoreTA=Simmio(lower=0x68006800,
upper=0x68006BFF,
name='L4CoreTA')
L4PerTA=Simmio(lower=0x68006C00,
upper=0x68006FFF,
name='L4PerTA')
Reserved3=Simmio(lower=0x68007000,
upper=0x6800FFFF,
name='Reserved3')
RTPM=Simmio(lower=0x68010000,
upper=0x680103FF,
name='RTPM')
Reserved4=Simmio(lower=0x68010400,
upper=0x680123FF,
name='Reserved4')
GPMCPM=Simmio(lower=0x68012400,
upper=0x680127FF,
name='GPMCPM')
OCMRAMPM=Simmio(lower=0x68012800,
upper=0x68012BFF,
name='OCMRAMPM')
OCMROMPM=Simmio(lower=0x68012C00,
upper=0x68012FFF,
name='OCMROMPM')
D2DPM=Simmio(lower=0x68013000,
upper=0x680133FF,
name='D2DPM')
Reserved5=Simmio(lower=0x68013400,
upper=0x68013FFF,
name='Reserved5')
IVA22PM=Simmio(lower=0x68014000,
upper=0x680143FF,
name='IVA22PM')
Reserved6=Simmio(lower=0x68014400,
upper=0x68FFFFFF,
name='Reserved6')
SMS=Simmio(lower=0x6C000000,
upper=0x6CFFFFFF,
name='SMS')
SDRC=Simmio(lower=0x6D000000,
upper=0x6DFFFFFF,
name='SDRC')
GPMC=Simmio(lower=0x6E000000,
upper=0x6EFFFFFF,
name='GPMC')
L4ID_SCM=Simmio(lower=0x48002000,
upper=0x48002FFF,
name="L4ID_SCM")
L4ID_SCM_TA=Simmio(lower=0x48003000,
upper=0x48003FFF,
name="L4ID_SCM_TA")
L4ID_CM_A=Simmio(lower=0x48004000,
upper=0x48005FFF,
name="L4ID_CM_A")
L4ID_CM_B=Simmio(lower=0x48006000,
upper=0x480067FF,
name="L4ID_CM_B")
L4ID_CM_TA=Simmio(lower=0x48007000,
upper=0x48007FFF,
name="L4ID_CM_TA")
L4ID_CORE_AP=Simmio(lower=0x48040000,
upper=0x480407FF,
name="L4ID_CORE_AP")
L4ID_CORE_IP=Simmio(lower=0x48040800,
upper=0x48040FFF,
name="L4ID_CORE_IP")
L4ID_CORE_LA=Simmio(lower=0x48041000,
upper=0x48041FFF,
name="L4ID_CORE_LA")
L4ID_DSI=Simmio(lower=0x4804FC00,
upper=0x4804FFFF,
name="L4ID_DSI")
L4ID_DSS=Simmio(lower=0x48050000,
upper=0x480503FF,
name="L4ID_DSS")
L4ID_DISPC=Simmio(lower=0x48050400,
upper=0x480507FF,
name="L4ID_DISPC")
L4ID_RFBI=Simmio(lower=0x48050800,
upper=0x48050BFF,
name="L4ID_RFBI")
L4ID_VENC=Simmio(lower=0x48050C00,
upper=0x48050FFF,
name="L4ID_VENC")
L4ID_DSS_TA=Simmio(lower=0x48051000,
upper=0x48051FFF,
name="L4ID_DSS_TA")
L4ID_SDMA=Simmio(lower=0x48056000,
upper=0x48056FFF,
name="L4ID_SDMA")
L4ID_SDMA_TA=Simmio(lower=0x48057000,
upper=0x48057FFF,
name="L4ID_SDMA_TA")
L4ID_I2C3=Simmio(lower=0x48060000,
upper=0x48060FFF,
name="L4ID_I2C3")
L4ID_I2C3_TA=Simmio(lower=0x48061000,
upper=0x48061FFF,
name="L4ID_I2C3_TA")
L4ID_USBTLL=Simmio(lower=0x48062000,
upper=0x48062FFF,
name="4ID_USBTLL")
L4ID_USBTLL_TA=Simmio(lower=0x48063000,
upper=0x48063FFF,
name="L4ID_USBTLL_TA")
L4ID_USBHOST=Simmio(lower=0x48064000,
upper=0x480643FF,
name="4ID_USBHOST")
L4ID_USBHOST_OHCI=Simmio(lower=0x48064400,
upper=0x480647FF,
name="L4ID_USBHOST_OHCI")
L4ID_USBHOST_EHCI=Simmio(lower=0x48064800,
upper=0x4806BFFF,
name="4ID_USBHOST_EHCI")
L4ID_USBHOST_TA=Simmio(lower=0x48065000,
upper=0x48065FFF,
name="L4ID_USBHOST_TA")
L4ID_UART1=Simmio(lower=0x4806A000,
upper=0x4806AFFF,
name="L4ID_UART1")
L4ID_UART1_TA=Simmio(lower=0x4806B000,
upper=0x4806BFFF,
name="L4ID_UART1_TA")
L4ID_UART2=Simmio(lower=0x4806C000,
upper=0x4806CFFF,
name="4ID_UART2")
L4ID_UART2_TA=Simmio(lower=0x4806D000,
upper=0x4806DFFF,
name="L4ID_UART2_TA")
L4ID_I2C1=Simmio(lower=0x48070000,
upper=0x48070FFF,
name="L4ID_I2C1")
L4ID_I2C1_TA=Simmio(lower=0x48071000,
upper=0x48071FFF,
name="L4ID_I2C1_TA")
L4ID_I2C2=Simmio(lower=0x48072000,
upper=0x48072FFF,
name="L4ID_I2C2")
L4ID_I2C2_TA=Simmio(lower=0x48073000,
upper=0x48073FFF,
name="L4ID_I2C2_TA")
L4ID_MCBSP1=Simmio(lower=0x48074000,
upper=0x48074FFF,
name="L4ID_MCBSP1")
L4ID_MCBSP1_TA=Simmio(lower=0x48075000,
upper=0x48075FFF,
name="L4ID_MCBSP1_TA")
L4ID_GPTIMER10=Simmio(lower=0x48086000,
upper=0x48086FFF,
name="L4ID_GPTIMER10")
L4ID_GPTIMER10_TA=Simmio(lower=0x48087000,
upper=0x48087FFF,
name="L4ID_GPTIMER10_TA")
L4ID_GPTIMER11=Simmio(lower=0x48088000,
upper=0x48088FFF,
name="4ID_GPTIMER11")
L4ID_GPTIMER11_TA=Simmio(lower=0x48089000,
upper=0x48089FFF,
name='L4ID_GPTIMER11_TA')
L4ID_MAILBOX=Simmio(lower=0x48094000,
upper=0x48094FFF,
name='L4ID_MAILBOX')
L4ID_MAILBOX_TA=Simmio(lower=0x48095000,
upper=0x48095FFF,
name='L4ID_MAILBOX_TA')
L4ID_MCBSP5=Simmio(lower=0x48096000,
upper=0x48096FFF,
name='L4ID_MCBSP5')
L4ID_MCBSP5_TA=Simmio(lower=0x48097000,
upper=0x48097FFF,
name='L4ID_MCBSP5_TA')
L4ID_MCSPI1=Simmio(lower=0x48098000,
upper=0x48098FFF,
name='L4ID_MCSPI1')
L4ID_MCSPI1_TA=Simmio(lower=0x48099000,
upper=0x48099FFF,
name='L4ID_MCSPI1_TA')
L4ID_MCSPI2=Simmio(lower=0x4809A000,
upper=0x4809AFFF,
name='L4ID_MCSPI2')
L4ID_MCSPI2_TA=Simmio(lower=0x4809B000,
upper=0x4809BFFF,
name='L4ID_MCSPI2_TA')
L4ID_MMCSDIO1=Simmio(lower=0x4809C000,
upper=0x4809CFFF,
name='L4ID_MMCSDIO1')
L4ID_MMCSDIO1_TA=Simmio(lower=0x4809D000,
upper=0x4809DFFF,
name='L4ID_MMCSDIO1_TA')
L4ID_MSPRO=Simmio(lower=0x4809E000,
upper=0x4809EFFF,
name='L4ID_MSPRO')
L4ID_MSPRO_TA=Simmio(lower=0x4809F000,
upper=0x4809FFFF,
name='L4ID_MSPRO_TA')
L4ID_HSUSBOTG=Simmio(lower=0x480AB000,
upper=0x480ABFFF,
name='L4ID_HSUSBOTG')
L4ID_HSUSBOTG_TA=Simmio(lower=0x480AC000,
upper=0x480ACFFF,
name='L4ID_HSUSBOTG_TA')
L4ID_MMCSDIO3=Simmio(lower=0x480AD000,
upper=0x480ADFFF,
name='L4ID_MMCSDIO3')
L4ID_MMCSDIO3_TA=Simmio(lower=0x480AE000,
upper=0x480AEFFF,
name='L4ID_MMCSDIO3_TA')
L4ID_HDQ1WIRE=Simmio(lower=0x480B2000,
upper=0x480B2FFF,
name='L4ID_HDQ1WIRE')
L4ID_HDQ1WIRE_TA=Simmio(lower=0x480B3000,
upper=0x480B2FFF,
name='L4ID_HDQ1WIRE_TA')
L4ID_MMCSDIO2=Simmio(lower=0x480B4000,
upper=0x480B4FFF,
name='L4ID_MMCSDIO2')
L4ID_MMCSDIO2_TA=Simmio(lower=0x480B5000,
upper=0x480B5FFF,
name='L4ID_MMCSDIO2_TA')
L4ID_ICRMPU=Simmio(lower=0x480B6000,
upper=0x480B6FFF,
name='L4ID_ICRMPU')
L4ID_ICRMPU_TA=Simmio(lower=0x480B7000,
upper=0x480B7FFF,
name='L4ID_ICRMPU_TA')
L4ID_MCSPI3=Simmio(lower=0x480B8000,
upper=0x480B8FFF,
name='L4ID_MCSPI3')
L4ID_MCSPI3_TA=Simmio(lower=0x480B9000,
upper=0x480B9FFF,
name='L4ID_MCSPI3_TA')
L4ID_MCSPI4=Simmio(lower=0x480BA000,
upper=0x480BAFFF,
name='L4ID_MCSPI4')
L4ID_MCSPI4_TA=Simmio(lower=0x480BB000,
upper=0x480BBFFF,
name='L4ID_MCSPI4_TA')
L4ID_CAMERAISP=Simmio(lower=0x480BC000,
upper=0x480BFFFF,
name='L4ID_CAMERAISP')
L4ID_CAMERAISP_TA=Simmio(lower=0x480C0000,
upper=0x480C0FFF,
name='L4ID_CAMERAISP_TA')
L4ID_SR1=Simmio(lower=0x480C9000,
upper=0x480C9FFF,
name='L4ID_SR1')
L4ID_SR1_TA=Simmio(lower=0x480CA000,
upper=0x480CAFFF,
name='L4ID_SR1_TA')
L4ID_SR2=Simmio(lower=0x480CB000,
upper=0x480CBFFF,
name='L4ID_SR2')
L4ID_SR2_TA=Simmio(lower=0x480CC000,
upper=0x480CCFFF,
name='L4ID_SR2_TA')
L4ID_ICRMODEM=Simmio(lower=0x480CD000,
upper=0x480CDFFF,
name='L4ID_ICRMODEM')
L4ID_ICRMODEM_TA=Simmio(lower=0x480CE000,
upper=0x480CEFFF,
name='L4ID_ICRMODEM_TA')
L4ID_GPTIMER12=Simmio(lower=0x48304000,
upper=0x48304FFF,
name='L4ID_GPTIMER12')
L4ID_GPTIMER12_TA=Simmio(lower=0x48305000,
upper=0x48305FFF,
name='L4ID_GPTIMER12_TA')
L4ID_PRM_A=Simmio(lower=0x48306000,
upper=0x48307FFF,
name='L4ID_PRM_A')
L4ID_PRM_TA=Simmio(lower=0x48309000,
upper=0x48309FFF,
name='L4ID_PRM_TA')
L4ID_TAP=Simmio(lower=0x4830A000,
upper=0x4830AFFF,
name='L4ID_TAP')
L4ID_TAP_TA=Simmio(lower=0x4830B000,
upper=0x4830BFFF,
name='L4ID_TAP_TA')
L4ID_GPIO1=Simmio(lower=0x48310000,
upper=0x48310FFF,
name='L4ID_GPIO1')
L4ID_GPIO1_TA=Simmio(lower=0x48311000,
upper=0x48311FFF,
name='L4ID_GPIO1_TA')
L4ID_WDTIMER2=Simmio(lower=0x48314000,
upper=0x48314FFF,
name='L4ID_WDTIMER2')
L4ID_WDTIMER2_TA=Simmio(lower=0x48315000,
upper=0x48315FFF,
name='L4ID_WDTIMER2_TA')
L4ID_GPTIMER1=Simmio(lower=0x48318000,
upper=0x48318FFF,
name='L4ID_GPTIMER1')
L4ID_GPTIMER1_TA=Simmio(lower=0x48319000,
upper=0x48319FFF,
name='L4ID_GPTIMER1_TA')
L4ID_32KTIMER=Simmio(lower=0x48320000,
upper=0x48320FFF,
name='L4ID_32KTIMER')
L4ID_32KTIMER_TA=Simmio(lower=0x48321000,
upper=0x48321FFF,
name='L4ID_32KTIMER_TA')
L4ID_WAKEUP_AP=Simmio(lower=0x48328000,
upper=0x483287FF,
name='L4ID_WAKEUP_AP')
L4ID_WAKEUP_C_IP=Simmio(lower=0x48328800,
upper=0x48328FFF,
name='L4ID_WAKEUP_C_IP')
L4ID_WAKEUP_LA=Simmio(lower=0x48329000,
upper=0x48329FFF,
name='L4ID_WAKEUP_LA')
L4ID_WAKEUP_E_IP=Simmio(lower=0x4832A000,
upper=0x4832A7FF,
name='L4ID_WAKEUP_E_IP')
L4ID_PER_AP=Simmio(lower=0x49000000,
upper=0x490007FF,
name='L4ID_PER_AP')
L4ID_PER_IP=Simmio(lower=0x49000800,
upper=0x49000FFF,
name='L4ID_PER_IP')
L4ID_PER_LA=Simmio(lower=0x49001000,
upper=0x49001FFF,
name='L4ID_PER_LA')
L4ID_UART3=Simmio(lower=0x49020000,
upper=0x49020FFF,
name='L4ID_UART3')
L4ID_UART3_TA=Simmio(lower=0x49021000,
upper=0x49021FFF,
name='L4ID_UART3_TA')
L4ID_MCBSP2=Simmio(lower=0x49022000,
upper=0x49022FFF,
name='L4ID_MCBSP2')
L4ID_MCBSP2_TA=Simmio(lower=0x49023000,
upper=0x49023FFF,
name='L4ID_MCBSP2_TA')
L4ID_MCBSP3=Simmio(lower=0x49024000,
upper=0x49024FFF,
name='L4ID_MCBSP3')
L4ID_MCBSP3_TA=Simmio(lower=0x49025000,
upper=0x49025FFF,
name='L4ID_MCBSP3_TA')
L4ID_MCBSP4=Simmio(lower=0x49026000,
upper=0x49026FFF,
name='L4ID_MCBSP4')
L4ID_MCBSP4_TA=Simmio(lower=0x49027000,
upper=0x49027FFF,
name='L4ID_MCBSP4_TA')
L4ID_MCBSP2S=Simmio(lower=0x49028000,
upper=0x49028FFF,
name='L4ID_MCBSP2S')
L4ID_MCBSP2S_TA=Simmio(lower=0x49029000,
upper=0x49029FFF,
name='L4ID_MCBSP2S_TA')
L4ID_MCBSP3S=Simmio(lower=0x4902A000,
upper=0x4902AFFF,
name='L4ID_MCBSP3S')
L4ID_MCBSP3S_TA=Simmio(lower=0x4902B000,
upper=0x4902BFFF,
name='L4ID_MCBSP3S_TA')
L4ID_WDTIMER3=Simmio(lower=0x49030000,
upper=0x49030FFF,
name='L4ID_WDTIMER3')
L4ID_WDTIMER3_TA=Simmio(lower=0x49031000,
upper=0x49031FFF,
name='L4ID_WDTIMER3_TA')
L4ID_GPTIMER2=Simmio(lower=0x49032000,
upper=0x49032FFF,
name='L4ID_GPTIMER2')
L4ID_GPTIMER2_TA=Simmio(lower=0x49033000,
upper=0x49033FFF,
name='L4ID_GPTIMER2_TA')
L4ID_GPTIMER3=Simmio(lower=0x49034000,
upper=0x49034FFF,
name='L4ID_GPTIMER3')
L4ID_GPTIMER3_TA=Simmio(lower=0x49035000,
upper=0x49035FFF,
name='L4ID_GPTIMER3_TA')
L4ID_GPTIMER4=Simmio(lower=0x49036000,
upper=0x49036FFF,
name='L4ID_GPTIMER4')
L4ID_GPTIMER4_TA=Simmio(lower=0x49037000,
upper=0x49037FFF,
name='L4ID_GPTIMER4_TA')
L4ID_GPTIMER5=Simmio(lower=0x49038000,
upper=0x49038FFF,
name='L4ID_GPTIMER5')
L4ID_GPTIMER5_TA=Simmio(lower=0x49039000,
upper=0x49039FFF,
name='L4ID_GPTIMER5_TA')
L4ID_GPTIMER6=Simmio(lower=0x4903A000,
upper=0x4903AFFF,
name='L4ID_GPTIMER6')
L4ID_GPTIMER6_TA=Simmio(lower=0x4903B000,
upper=0x4903BFFF,
name='L4ID_GPTIMER6_TA')
L4ID_GPTIMER7=Simmio(lower=0x4903C000,
upper=0x4903CFFF,
name='L4ID_GPTIMER7')
L4ID_GPTIMER7_TA=Simmio(lower=0x4903D000,
upper=0x4903DFFF,
name='L4ID_GPTIMER7_TA')
L4ID_GPTIMER8=Simmio(lower=0x4903E000,
upper=0x4903EFFF,
name='L4ID_GPTIMER8')
L4ID_GPTIMER8_TA=Simmio(lower=0x4903F000,
upper=0x4903FFFF,
name='L4ID_GPTIMER8_TA')
L4ID_GPTIMER9=Simmio(lower=0x49040000,
upper=0x49040FFF,
name='L4ID_GPTIMER9')
L4ID_GPTIMER9_TA=Simmio(lower=0x49041000,
upper=0x49041FFF,
name='L4ID_GPTIMER9_TA')
L4ID_UART4=Simmio(lower=0x49042000,
upper=0x49042FFF,
name='L4ID_UART4')
L4ID_UART4_TA=Simmio(lower=0x49043000,
upper=0x4904FFFF,
name='L4ID_UART4_TA')
L4ID_GPIO2=Simmio(lower=0x49050000,
upper=0x49050FFF,
name='L4ID_GPIO2')
L4ID_GPIO2_TA=Simmio(lower=0x49051000,
upper=0x49051FFF,
name='L4ID_GPIO2_TA')
L4ID_GPIO3=Simmio(lower=0x49052000,
upper=0x49052FFF,
name='L4ID_GPIO3')
L4ID_GPIO3_TA=Simmio(lower=0x49053000,
upper=0x49053FFF,
name='L4ID_GPIO3_TA')
L4ID_GPIO4=Simmio(lower=0x49054000,
upper=0x49054FFF,
name='L4ID_GPIO4')
L4ID_GPIO4_TA=Simmio(lower=0x49055000,
upper=0x49055FFF,
name='L4ID_GPIO4_TA')
L4ID_GPIO5=Simmio(lower=0x49056000,
upper=0x49056FFF,
name='L4ID_GPIO5')
L4ID_GPIO5_TA=Simmio(lower=0x49057000,
upper=0x49057FFF,
name='L4ID_GPIO5_TA')
L4ID_GPIO6=Simmio(lower=0x49058000,
upper=0x49058FFF,
name='L4ID_GPIO6')
L4ID_GPIO6_TA=Simmio(lower=0x49059000,
upper=0x49059FFF,
name='L4ID_GPIO6_TA')
L4ID_EMU_AP=Simmio(lower=0x54006000,
upper=0x540067FF,
name='L4ID_EMU_AP')
L4ID_EMU_IP_C=Simmio(lower=0x54006800,
upper=0x54006FFF,
name='L4ID_EMU_IP_C')
L4ID_EMU_LA=Simmio(lower=0x54007000,
upper=0x54007FFF,
name='L4ID_EMU_LA')
L4ID_EMU_IP_DAP=Simmio(lower=0x54008000,
upper=0x540087FF,
name='L4ID_EMU_IP_DAP')
L4ID_MPUEMU=Simmio(lower=0x54010000,
upper=0x54017FFF,
name='L4ID_MPUEMU')
L4ID_MPUEMU_TA=Simmio(lower=0x54018000,
upper=0x54018FFF,
name='L4ID_MPUEMU_TA')
L4ID_TPIU=Simmio(lower=0x54019000,
upper=0x54019FFF,
name='L4ID_TPIU')
L4ID_TPIU_TA=Simmio(lower=0x5401A000,
upper=0x5401AFFF,
name='L4ID_TPIU_TA')
L4ID_ETB=Simmio(lower=0x5401B000,
upper=0x5401BFFF,
name='L4ID_ETB')
L4ID_ETB_TA=Simmio(lower=0x5401C000,
upper=0x5401CFFF,
name='L4ID_ETB_TA')
L4ID_DAPCTL=Simmio(lower=0x5401D000,
upper=0x5401DFFF,
name='L4ID_DAPCTL')
L4ID_DAPCTL_TA=Simmio(lower=0x5401E000,
upper=0x5401EFFF,
name='L4ID_DAPCTL_TA')
L4ID_SDTI_TA=Simmio(lower=0x5401F000,
upper=0x5401FFFF,
name='L4ID_SDTI_TA')
L4ID_SDTI_CFG=Simmio(lower=0x54500000,
upper=0x5450FFFF,
name='L4ID_SDTI_CFG')
L4ID_SDTI=Simmio(lower=0x54600000,
upper=0x546FFFFF,
name='L4ID_SDTI')
L4ID_EMU_PRM_A=Simmio(lower=0x54706000,
upper=0x54707FFF,
name='L4ID_EMU_PRM_A')
L4ID_EMU_PRM_B=Simmio(lower=0x54708000,
upper=0x547087FF,
name='L4ID_EMU_PRM_B')
L4ID_EMU_PRM_TA=Simmio(lower=0x54709000,
upper=0x54709FFF,
name='L4ID_EMU_PRM_TA')
L4ID_EMU_GPIO1=Simmio(lower=0x54710000,
upper=0x54710FFF,
name='L4ID_EMU_GPIO1')
L4ID_EMU_GPIO1_TA=Simmio(lower=0x54711000,
upper=0x54711FFF,
name='L4ID_EMU_GPIO1_TA')
L4ID_EMU_WDTM2=Simmio(lower=0x54714000,
upper=0x54714FFF,
name='L4ID_EMU_WDTM2')
L4ID_EMU_WDTM2_TA=Simmio(lower=0x54715000,
upper=0x54715FFF,
name='L4ID_EMU_WDTM2_TA')
L4ID_EMU_GPTM1=Simmio(lower=0x54718000,
upper=0x54718FFF,
name='L4ID_EMU_GPTM1')
L4ID_EMU_GPTM1_TA=Simmio(lower=0x54719000,
upper=0x54719FFF,
name='L4ID_EMU_GPTM1_TA')
L4ID_EMU_32KTM=Simmio(lower=0x54720000,
upper=0x54720FFF,
name='L4ID_EMU_32KTM')
L4ID_EMU_32KTM_TA=Simmio(lower=0x54721000,
upper=0x54721FFF,
name='L4ID_EMU_32KTM_TA')
L4ID_EMU_WKUP_AP=Simmio(lower=0x54728000,
upper=0x547287FF,
name='L4ID_EMU_WKUP_AP')
L4ID_EMU_WKUP_IPC=Simmio(lower=0x54728800,
upper=0x54728FFF,
name='L4ID_EMU_WKUP_IPC')
L4ID_EMU_WKUP_LA=Simmio(lower=0x54729000,
upper=0x54729FFF,
name='L4ID_EMU_WKUP_LA')
L4ID_EMU_WKUP_IPE=Simmio(lower=0x5472A000,
upper=0x5472A7FF,
name='L4ID_EMU_WKUP_IPE')

regions = [L3RT,
L3SI,
Reserved0,
MPUSSIA,
IVA22SSIA,
SGXSSIA,
SMSTA,
GPMCTA,
OCMRAMTA,
OCMROMTA,
D2DIA,
D2DTA,
Reserved1,
HSUSBHOSTIA,
HSUSBOTGIA,
Reserved2,
sDMARDIA,
sDMAWRIA,
DisplaySSIA,
CAMERAISPIA,
DAPIA,
IVA22SSTA,
SGXSSTA,
L4CoreTA,
L4PerTA,
Reserved3,
RTPM,
Reserved4,
GPMCPM,
OCMRAMPM,
OCMROMPM,
D2DPM,
Reserved5,
IVA22PM,
Reserved6,
SMS,
SDRC,
GPMC,
L4ID_SCM,
L4ID_SCM_TA,
L4ID_CM_A,
L4ID_CM_B,
L4ID_CM_TA,
L4ID_CORE_AP,
L4ID_CORE_IP,
L4ID_CORE_LA,
L4ID_DSI,
L4ID_DSS,
L4ID_DISPC,
L4ID_RFBI,
L4ID_VENC,
L4ID_DSS_TA,
L4ID_SDMA,
L4ID_SDMA_TA,
L4ID_I2C3,
L4ID_I2C3_TA,
L4ID_USBTLL,
L4ID_USBTLL_TA,
L4ID_USBHOST,
L4ID_USBHOST_OHCI,
L4ID_USBHOST_EHCI,
L4ID_USBHOST_TA,
L4ID_UART1,
L4ID_UART1_TA,
L4ID_UART2,
L4ID_UART2_TA,
L4ID_I2C1,
L4ID_I2C1_TA,
L4ID_I2C2,
L4ID_I2C2_TA,
L4ID_MCBSP1,
L4ID_MCBSP1_TA,
L4ID_GPTIMER10,
L4ID_GPTIMER10_TA,
L4ID_GPTIMER11,
L4ID_GPTIMER11_TA,
L4ID_MAILBOX,
L4ID_MAILBOX_TA,
L4ID_MCBSP5,
L4ID_MCBSP5_TA,
L4ID_MCSPI1,
L4ID_MCSPI1_TA,
L4ID_MCSPI2,
L4ID_MCSPI2_TA,
L4ID_MMCSDIO1,
L4ID_MMCSDIO1_TA,
L4ID_MSPRO,
L4ID_MSPRO_TA,
L4ID_HSUSBOTG,
L4ID_HSUSBOTG_TA,
L4ID_MMCSDIO3,
L4ID_MMCSDIO3_TA,
L4ID_HDQ1WIRE,
L4ID_HDQ1WIRE_TA,
L4ID_MMCSDIO2,
L4ID_MMCSDIO2_TA,
L4ID_ICRMPU,
L4ID_ICRMPU_TA,
L4ID_MCSPI3,
L4ID_MCSPI3_TA,
L4ID_MCSPI4,
L4ID_MCSPI4_TA,
L4ID_CAMERAISP,
L4ID_CAMERAISP_TA,
L4ID_SR1,
L4ID_SR1_TA,
L4ID_SR2,
L4ID_SR2_TA,
L4ID_ICRMODEM,
L4ID_ICRMODEM_TA,
L4ID_GPTIMER12,
L4ID_GPTIMER12_TA,
L4ID_PRM_A,
L4ID_PRM_TA,
L4ID_TAP,
L4ID_TAP_TA,
L4ID_GPIO1,
L4ID_GPIO1_TA,
L4ID_WDTIMER2,
L4ID_WDTIMER2_TA,
L4ID_GPTIMER1,
L4ID_GPTIMER1_TA,
L4ID_32KTIMER,
L4ID_32KTIMER_TA,
L4ID_WAKEUP_AP,
L4ID_WAKEUP_C_IP,
L4ID_WAKEUP_LA,
L4ID_WAKEUP_E_IP,
L4ID_PER_AP,
L4ID_PER_IP,
L4ID_PER_LA,
L4ID_UART3,
L4ID_UART3_TA,
L4ID_MCBSP2,
L4ID_MCBSP2_TA,
L4ID_MCBSP3,
L4ID_MCBSP3_TA,
L4ID_MCBSP4,
L4ID_MCBSP4_TA,
L4ID_MCBSP2S,
L4ID_MCBSP2S_TA,
L4ID_MCBSP3S,
L4ID_MCBSP3S_TA,
L4ID_WDTIMER3,
L4ID_WDTIMER3_TA,
L4ID_GPTIMER2,
L4ID_GPTIMER2_TA,
L4ID_GPTIMER3,
L4ID_GPTIMER3_TA,
L4ID_GPTIMER4,
L4ID_GPTIMER4_TA,
L4ID_GPTIMER5,
L4ID_GPTIMER5_TA,
L4ID_GPTIMER6,
L4ID_GPTIMER6_TA,
L4ID_GPTIMER7,
L4ID_GPTIMER7_TA,
L4ID_GPTIMER8,
L4ID_GPTIMER8_TA,
L4ID_GPTIMER9,
L4ID_GPTIMER9_TA,
L4ID_UART4,
L4ID_UART4_TA,
L4ID_GPIO2,
L4ID_GPIO2_TA,
L4ID_GPIO3,
L4ID_GPIO3_TA,
L4ID_GPIO4,
L4ID_GPIO4_TA,
L4ID_GPIO5,
L4ID_GPIO5_TA,
L4ID_GPIO6,
L4ID_GPIO6_TA,
L4ID_EMU_AP,
L4ID_EMU_IP_C,
L4ID_EMU_LA,
L4ID_EMU_IP_DAP,
L4ID_MPUEMU,
L4ID_MPUEMU_TA,
L4ID_TPIU,
L4ID_TPIU_TA,
L4ID_ETB,
L4ID_ETB_TA,
L4ID_DAPCTL,
L4ID_DAPCTL_TA,
L4ID_SDTI_TA,
L4ID_SDTI_CFG,
L4ID_SDTI,
L4ID_EMU_PRM_A,
L4ID_EMU_PRM_B,
L4ID_EMU_PRM_TA,
L4ID_EMU_GPIO1,
L4ID_EMU_GPIO1_TA,
L4ID_EMU_WDTM2,
L4ID_EMU_WDTM2_TA,
L4ID_EMU_GPTM1,
L4ID_EMU_GPTM1_TA,
L4ID_EMU_32KTM,
L4ID_EMU_32KTM_TA,
L4ID_EMU_WKUP_AP,
L4ID_EMU_WKUP_IPC,
L4ID_EMU_WKUP_LA,
L4ID_EMU_WKUP_IPE]