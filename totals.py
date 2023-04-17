import requests
import time
import logging
from tqdm import tqdm
import pandas as pd
from datetime import date

class Virus:
    def __init__(self,
                 df = None,
                 src  = 'src_ip',
                 dest = 'dest_ip',
                 mykey = None,
                 url = 'https://www.virustotal.com/vtapi/v2/url/scan'
        ): 
        self.src_ip = df[src]
        self.mykey = mykey
        self.dest_ip = df[dest]
        self.src_result = []
        self.dest_result = []
        self.url = url
        self.result = df 
        self.url_report = 'https://www.virustotal.com/vtapi/v2/url/report'
    
    def __searching(self,scan_url = 'http://naver.com'):
        params = {'apikey': self.mykey, 'url': scan_url}
        try:
            response_scan = requests.post(self.url, data=params)
            result_scan = response_scan.json()
            scan_id = result_scan['scan_id']  # 결과를 출력을 위해 scan_id 값 저장
            self.url_report_params = {'apikey': self.mykey, 'resource': scan_id}
            response_report = requests.get(self.url_report, params=self.url_report_params)
            report = response_report.json()  # 결과 값을 report에 json형태로 저장
            report_verbose_msg = report.get('verbose_msg')
            report_scans = report.get('scans')  # scans 값 저장
            report_scans_vendors = list(report['scans'].keys())  # Vendor 저장
            report_scans_vendors_cnt = len(report_scans_vendors)  # 길이 저장
            report_scan_data = report.get('scan_data')
            result = []
            vendorname = []
            vendorresult = []
            vendordetected = []
            numbers = 1
            for vendor in report_scans_vendors:
                outputs = report_scans[vendor]
                outputs_result = report_scans[vendor].get('result')
                outputs_detected = report_scans[vendor].get('detected')
                if outputs_result != 'clean site':
                    if outputs_result != 'unrated site':
                        pass
                        vendorname.append(outputs)
                        vendorresult.append(outputs_result)
                        vendordetected.append(outputs_detected)
            result.append([vendorname,vendorresult,vendordetected])
        except Exception as e:
            logging.warning(e)
            print('\n'+scan_url+'\n')
            result = 'error'
        return result

    def __detect_preprocessing(self,ips):
        tmp = list(set(ips))  
        text = []
        text2 = []
        result = []
        for i in tqdm(range(len(tmp))):
            time.sleep(16) #1건당 탐지 시간 
            text.append((self.__searching(tmp[i])))
        for i in tqdm(range(len(text))):
            if text[i] == 'error':
                print(f'{tmp[i]} ip가 에러가 나와 한번더 시도 합니다.')
                time.sleep(30)
                text2.append((self.__searching(tmp[i])))
            else:
                text2.append(text[i])
        ip_dict= dict(zip(tmp,text2))
        for ip in ips:
            result.append(ip_dict[ip])  
        return result 
    
    def detect(self):
        self.result['src_result'] = self.__detect_preprocessing(self.src_ip)   
        time.sleep(30)
        self.result['dest_result'] = self.__detect_preprocessing(self.dest_ip)
        self.result['result'] =  self.result['src_result'].apply(lambda x : str(x)) + self.result['dest_result'].apply(lambda x : str(x))
        self.result['virus_detect'] = self.result['result'].apply(lambda x : False if x == '[[[], [], []]][[[], [], []]]' else  
                                                                      x  if 'error' in x else True)
        del self.result['result']
        return self.result 

if __name__ == '__main__':
    from config import *
    #with open('apikey2.txt') as file:
    #    my_apikey = file.read()
    my_apikey = apikey2
    filepath  = f'{date.today()}.csv'
    df = pd.read_csv(filepath).head(1) 
    Virus(src="src_ip" , dest="dest_ip",df= df,mykey=my_apikey).detect()
    result = virus.detect()
    result.to_csv(f'detect{filepath}',index=False)
