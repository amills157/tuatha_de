import os
import csv
import argparse

import pandas as pd

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="CHANGEME")

    parser.add_argument("-dir", help="Input dir that holds node files", required = True)

    args = parser.parse_args()
    base_dir = args.dir

    files = os.listdir(base_dir)

    ebid_dict = {}

    for f in files:
        if f.endswith(".csv"):
            target_csv = os.path.join(base_dir, f)


            df = pd.read_csv(target_csv)

            df = df.loc[:, (df != 0).any(axis=0)]

            col_list = []

            for col in df.columns:
                if "NETWORK" in col:
                    col_list.append(col)

            if any("crit" in s for s in col_list):
                print(f)
            
            # if len(col_list) > 1:
            #     print(f)
            # else:
            #     if len(col_list) == 1:
            #         if "neg" not in col_list[0]:
            #             print(f)

            
                    

    #         for col in df.columns:
    #             key = col
    #             value = df.iloc[0][col]

    #             if key not in ebid_dict:
    #                 ebid_dict[key] = value
    #             else:
    #                 ebid_dict[key] += value

    # print(ebid_dict)

    # with open(base_dir + '_Summary.csv', 'w') as csv_file:  
    #     writer = csv.writer(csv_file)
    #     for key, value in ebid_dict.items():
    #         writer.writerow([key, value])