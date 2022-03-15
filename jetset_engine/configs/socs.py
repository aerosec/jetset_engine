import configs.cmu_config as cmu
import configs.beagle_config as beagle
import configs.rpi_config as rpi
import configs.stm32f4_config as stm32f4
import configs.cnc_config as cnc
import configs.robot_config as robot
import configs.gateway_config as gateway
import configs.drone_config as drone
import configs.reflow_oven_config as reflow_oven

import configs.console_config as console
import configs.heat_press_config as heat_press
import configs.steering_control_config as steering_control


socs = {
 	"cmu" : cmu,
 	"rpi" : rpi,
 	"beagle" : beagle,
 	"stm32f4" : stm32f4,
	"cnc" : cnc,
	"robot" : robot,
	"gateway" : gateway,
	"drone" : drone,
	"reflow_oven" : reflow_oven,  
	"console" : console,
	"heat_press" : heat_press,
	"steering_control" : steering_control
}

def get_soc(socname):
	soc = socs.get(socname)
	if soc == None:
		raise Exception("Invalid soc name, try (console | heat_press | steering_control | cnc | beagle | rpi | stm32f4)")
	else:
		return soc

def get_project(socname):
	soc = get_soc(socname)
	return soc.get_project()

def get_target(socname):
	soc = get_soc(socname)
	return soc.target

def get_avoid(socname):
	soc = get_soc(socname)
	if hasattr(soc, 'avoid'):
		return soc.avoid
	return []

def get_regions(socname):
	soc = get_soc(socname)
	return soc.regions

def get_arch(socname):
	soc = get_soc(socname)
	return soc.arch

def get_arch_num(socname):
	soc = get_soc(socname)
	return soc.arch_num
