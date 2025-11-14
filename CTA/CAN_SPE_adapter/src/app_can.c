#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(net_echo_client_sample, LOG_LEVEL_INF);

#include "common.h"
#include "app_can.h"
#include <zephyr/kernel.h>


/* Change these to match your board/device tree aliases */
#define CAN_FILTER_DATA    CAN_FILTER_IDE //BIT(2)

const struct device *const can_dev = DEVICE_DT_GET(DT_CHOSEN(zephyr_canbus));

/* CAN RX callback: called in interrupt context */
static void can_rx_cb(const struct device *dev,
                      struct can_frame *frame) 
{
	static struct can_frame frame_to_send = {0};
    
	memcpy(&frame_to_send, frame, sizeof(struct can_frame));

    uint8_t dbg[128] = {0};
	for(int i = 0; i < frame->dlc ; i++)
	{
		sprintf(&dbg[i*3],"%02X ",frame_to_send.data[i]);	
	}	
	LOG_DBG("Received CAN Frame. ID : 0x%02X , Frame : %s",frame_to_send.id,dbg);

	while (k_msgq_put(&can_msgq, &frame, K_NO_WAIT) != 0) {
		/* message queue is full: purge old data & try again */
		k_msgq_purge(&can_msgq);
	}	
}

static void init_can(void)
{
    struct can_filter filter = {
        .id     = 0U,
        .mask   = 0U,          /* accept all IDs */
        .flags  = CAN_FILTER_DATA,
    };
   

    if (!can_dev) {
        LOG_ERR("CAN device not found");
        return;
    }
	
	if (!device_is_ready(can_dev)) {
		LOG_ERR("CAN device %s is not ready", can_dev->name);
		return;
	}

	can_set_mode(can_dev, CAN_MODE_NORMAL);


	int err = can_start(can_dev);
	if (err != 0) {
		LOG_ERR("Error starting CAN controller (err %d)", err);
		return;
	}

	 /* Install filter + RX callback */
    int ret = can_add_rx_filter_msgq(can_dev, &can_msgq, &filter);  
	if (ret < 0) {
  		LOG_ERR("Unable to add rx msgq [%d]", ret);
	}  
	ret = can_add_rx_filter(can_dev,can_rx_cb, NULL, &filter);
	if (ret < 0) {
  		LOG_ERR("Unable to add rx filter cb [%d]", ret);
	}

	LOG_INF("CAN filter return : %d", ret);
}

void can_thread(void* arg1, void* arg2, void* arg3)
{
   init_can();


   while(1)
   {
		can_frame_t frame = {0};
		int spe_rcv = k_msgq_get(&spe_msgq, &frame, K_FOREVER);
	    if(spe_rcv == 0) {
			LOG_DBG("CAN ID: 0x%03X DLC: %d Data: %02X %02X %02X %02X %02X %02X %02X %02X",
				frame.id, frame.dlc,
				frame.data[0], frame.data[1], frame.data[2], frame.data[3],
				frame.data[4], frame.data[5], frame.data[6], frame.data[7]);

			int ret = -1;

			ret = can_send(can_dev, &frame, K_NO_WAIT, NULL, NULL);
			if (ret != 0) {
					LOG_ERR("Sending failed [%d]", ret);
			}	
			else{
				LOG_DBG("CAN frame sent");
			}
			//Received CAN frame, send it over TCP
		}	
	}
}