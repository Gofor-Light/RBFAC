from Tree import *
from Cover import *
from traceable_revocable_hidden_clear import *
from time import *

def main():
    d = 10
    trial = 10

    Test_Setup = False
    Test_KeyGen = False
    Test_Hash = False
    Test_Verify = False
    Test_Decrypt = False
    Test_AdaptM = False
    Test_AdaptBM = False
    Test_AdaptP = False
    Test_AdaptCM = False
    Test_Adapt2P = True
    Test_Trace = False
    Test_CTUpdate = False
    Test_TKGen = False
    Test_verifyTK = False

    #系统用户列表
    U = ['A','B','C','D','E']
    tree = Tree()
    list_u_id = tree.creatTree2(U)
    list_id_u = {val: key for key, val in list_u_id.items()}
    #初始化双线性映射
    grp = PairingGroup("SS512")

    TRH = TRH_CPabe(grp)

    # 初始化系统
    (mpk, msk, sk_tc, pk_tc) = TRH.Setup(tree)

    # 密钥生成
    u = 'E'
    id = list_u_id[u]
    u_node_list = tree.SearchU(tree.root, u)
    u_node = u_node_list[1]
    S = {'IDENTITY':'teacher', 'SEX':'female'}

    if Test_TKGen:
        d=10      # number of attributes
        NN = 100
        
        f = open('result_TKGen.txt', 'w+')
        while d <= NN:
            f.write("(" + str(d) + ",")
            T = 0
            Temp = 0
            start = 0
            end = 0

            #令牌参数生成
            n_time = 1  # n-times modifications
            type_m = 'T_1tk'  # type_m = ['t_1tk', 't_ntk',' b_1tk', 'b_ntk','T_1tk', 'T_ntk',' B_1tk', 'B_ntk']
            level_m= ['t_1tk', 't_ntk',' b_1tk', 'b_ntk','T_1tk', 'T_ntk',' B_1tk', 'B_ntk']  # level of privilege
            index = "B100-T12"  # index of transactions or block (e.g. trasnaction NO.T12 of block NO.B100)
            req_tk = [type_m, u, n_time,index]  # request token

            for i in range(trial):
                start = time()
                TRH.TKGen(mpk,sk_tc, pk_tc, req_tk)
                end = time()
                Temp = end - start
                T += Temp
            T = T / trial
            f.write(str(T) + ")\n")
            d += 10
        f.close()

    if Test_verifyTK:
        d=10      # number of attributes
        NN = 100
        
        f = open('result_verifyTK.txt', 'w+')
        while d <= NN:
            f.write("(" + str(d) + ",")
            T = 0
            Temp = 0
            start = 0
            end = 0

            #令牌参数生成
            n_time = 1  # n-times modifications
            type_m = 'T_1tk'  # type_m = ['t_1tk', 't_ntk',' b_1tk', 'b_ntk','T_1tk', 'T_ntk',' B_1tk', 'B_ntk']
            level_m= ['t_1tk', 't_ntk',' b_1tk', 'b_ntk','T_1tk', 'T_ntk',' B_1tk', 'B_ntk']  # level of privilege
            index = "B100-T12"  # index of transactions or block (e.g. trasnaction NO.T12 of block NO.B100)
            req_tk = [type_m, u, n_time,index]  # request token
            ed_tk = TRH.TKGen(mpk,sk_tc, pk_tc, req_tk)

            for i in range(trial):
                start = time()
                TRH.verifyTK(mpk, ed_tk, pk_tc)
                end = time()
                Temp = end - start
                T += Temp
            T = T / trial
            f.write(str(T) + ")\n")
            d += 10
        f.close()

    if Test_Setup:
        d=10      # number of attributes
        NN = 100
        
        f = open('result_Setup.txt', 'w+')
        while d <= NN:
            f.write("(" + str(d) + ",")
            T = 0
            Temp = 0
            start = 0
            end = 0
            for i in range(trial):
                start = time()
                (mpk, msk, sk_tc, pk_tc) = TRH.Setup(tree)
                end = time()
                Temp = end - start
                T += Temp
            T = T / trial
            f.write(str(T) + ")\n")
            d += 10
        f.close()


    sk = TRH.KeyGen(u_node, msk, mpk, S)

    if Test_KeyGen:
        d=10      # number of attributes
        NN = 100
        
        f = open('result_keygen.txt', 'w+')
        while d <= NN:
            f.write("(" + str(d) + ",")
            T = 0
            Temp = 0
            start = 0
            end = 0
            S_test = {f'0{i+1}': str(i+1) for i in range(d)}
            for i in range(trial):
                start = time()
                sk = TRH.KeyGen(u_node, msk, mpk, S_test)
                end = time()
                Temp = end - start
                T += Temp
            T = T / trial
            f.write(str(T) + ")\n")
            d += 10
        f.close()

   
    # 哈希生成
    policy = '(identity and sex)'
    attri_list = {'IDENTITY': 'teacher', 'SEX': 'female'}
    W = {'policy': policy, 'T':attri_list}
    m = grp.random(GT)
    R = []
    R_node = []
    for i in R:
        temp = tree.SearchU(tree.root, i)
        R_node.append(temp[1])
    mincover,_ = cover(mpk['Tree'], R_node)
    

    if Test_Hash:
        d=10      # number of attributes
        NN = 100
        print ("Hash Bench")
        f = open('result_hash.txt', 'w+')
        while d <= NN:
            f.write("(" + str(d) + ",")
            T = 0
            Temp = 0
            start = 0
            end = 0
            policy_str=""
            for j in range(d):
                if j != d - 1:
                    policy_str += "( 0" + str(2*j + 1) + " and 0" + str(2*j + 2) + " )" + " or "
                else:
                    policy_str += "( 0" + str(2*j + 1) + " and 0" + str(2*j + 2) + " )"

            # 创建attri_list映射表
            W_attri_list = {f'0{i+1}': str(i+1) for i in range(2*d)}

            # 更新W字典
            W_test = {'policy': policy_str, 'T': W_attri_list}
            for i in range(trial):
                start = time()
                TRH.Hash(mpk, m, W_test,mincover)
                end = time()
                Temp = end - start
                T += Temp
            T = T / trial
            f.write(str(T) + ")\n")
            d += 10
        f.close()

    if Test_Verify:
        d=10      # number of attributes
        NN = 100
        print ("Verify Bench")
        f = open('result_verify.txt', 'w+')
        while d <= NN:
            f.write("(" + str(d) + ",")
            T = 0
            Temp = 0
            start = 0
            end = 0
            policy_str=""
            for j in range(d):
                if j != d - 1:
                    policy_str += "( 0" + str(2*j + 1) + " and 0" + str(2*j + 2) + " )" + " or "
                else:
                    policy_str += "( 0" + str(2*j + 1) + " and 0" + str(2*j + 2) + " )"

            # 创建attri_list映射表
            W_attri_list = {f'0{i+1}': str(i+1) for i in range(2*d)}

            # 更新W字典
            W_test = {'policy': policy_str, 'T': W_attri_list}
            hash_text = TRH.Hash(mpk, m, W_test,mincover)

            p_prime, b, random_r = hash_text['p_prime'], hash_text['b'], hash_text['random_r']
            Cm, Ct = hash_text['Cm'], hash_text['Ct']
            Ck, K,WW, X = hash_text['Ck'], hash_text['K'], hash_text['WW'], hash_text['X']
            keypair_pk, epk = hash_text['keypair_pk'], hash_text['epk']
            c, sigma = hash_text['c'], hash_text['sigma']

            for i in range(trial):
                start = time()
                TRH.VerifyM(mpk, m, p_prime, b, random_r, c, epk, sigma, keypair_pk,WW, K, X)
                end = time()
                Temp = end - start
                T += Temp
                
            T = T / trial
            f.write(str(T) + ")\n")
            d += 10
        f.close()

    if Test_Decrypt:
        d=10      # number of attributes
        NN = 10
        print ("Decrypt Bench")
        f = open('result_decrypt.txt', 'w+')
        while d <= NN:
            f.write("(" + str(d) + ",")
            T = 0
            Temp = 0
            start = 0
            end = 0
            S_test = {f'0{i+1}': str(i+1) for i in range(2*d)}
            sk = TRH.KeyGen(u_node, msk, mpk, S_test)
            print(S_test)
            policy_str=""
            for j in range(d):
                if j != d - 1:
                    policy_str += "( 0" + str(2*j + 1) + " and 0" + str(2*j + 2) + " )" + " or "
                else:
                    policy_str += "( 0" + str(2*j + 1) + " and 0" + str(2*j + 2) + " )"

            # 创建attri_list映射表
            W_attri_list = {f'0{i+1}': str(i+1) for i in range(2*d)}

            # 更新W字典
            W_test = {'policy': policy_str, 'T': W_attri_list}
            hash_text = TRH.Hash(mpk, m, W_test,mincover)

            Cm, Ct = hash_text['Cm'], hash_text['Ct']

            for i in range(trial):
                start = time()
                m_text = TRH.Decrypt(u_node, mpk, Cm, sk,mincover)
                end = time()
                Temp = end - start
                T += Temp
            print(m_text == m)
            T = T / trial
            f.write(str(T) + ")\n")
            d += 10
        f.close()


    if Test_AdaptM:
        d=10      # number of attributes
        NN = 10
        print ("Adapt Bench")
        f = open('result_adaptM.txt', 'w+')
        while d <= NN:
            f.write("(" + str(d) + ",")
            T = 0
            Temp = 0
            start = 0
            end = 0
            S_test = {f'0{i+1}': str(i+1) for i in range(2*d)}
            sk = TRH.KeyGen(u_node, msk, mpk, S_test)
            print(S_test)
            policy_str=""
            for j in range(d):
                if j != d - 1:
                    policy_str += "( 0" + str(2*j + 1) + " and 0" + str(2*j + 2) + " )" + " or "
                else:
                    policy_str += "( 0" + str(2*j + 1) + " and 0" + str(2*j + 2) + " )"

            # 创建attri_list映射表
            W_attri_list = {f'0{i+1}': str(i+1) for i in range(2*d)}

            # 更新W字典
            W_test = {'policy': policy_str, 'T': W_attri_list}
            hash_text = TRH.Hash(mpk, m, W_test,mincover)

            p_prime, b, random_r = hash_text['p_prime'], hash_text['b'], hash_text['random_r']
            Cm, Ct = hash_text['Cm'], hash_text['Ct']
            Ck, K,WW, X = hash_text['Ck'], hash_text['K'], hash_text['WW'], hash_text['X']
            keypair_pk, epk = hash_text['keypair_pk'], hash_text['epk']
            c, sigma = hash_text['c'], hash_text['sigma']

            for i in range(trial):
                start = time()
                TRH.AdaptM(u_node, sk, mpk, m, p_prime, b, random_r, Ct,mincover)
                end = time()
                Temp = end - start
                T += Temp
            T = T / trial
            f.write(str(T) + ")\n")
            d += 10
        f.close()
    

    if Test_AdaptBM:
        d=10      # number of attributes
        NN = 10
        print ("Adapt Bench")
        f = open('result_adaptBM.txt', 'w+')
        while d <= NN:
            f.write("(" + str(d) + ",")
            T = 0
            Temp = 0
            start = 0
            end = 0
            S_test = {f'0{i+1}': str(i+1) for i in range(2*d)}
            sk = TRH.KeyGen(u_node, msk, mpk, S_test)
            print(S_test)
            policy_str=""
            for j in range(d):
                if j != d - 1:
                    policy_str += "( 0" + str(2*j + 1) + " and 0" + str(2*j + 2) + " )" + " or "
                else:
                    policy_str += "( 0" + str(2*j + 1) + " and 0" + str(2*j + 2) + " )"

            # 创建attri_list映射表
            W_attri_list = {f'0{i+1}': str(i+1) for i in range(2*d)}

            # 更新W字典
            W_test = {'policy': policy_str, 'T': W_attri_list}
            hash_text = TRH.Hash(mpk, m, W_test,mincover)

            p_prime, b, random_r = hash_text['p_prime'], hash_text['b'], hash_text['random_r']
            Cm, Ct = hash_text['Cm'], hash_text['Ct']
            Ck, K,WW, X = hash_text['Ck'], hash_text['K'], hash_text['WW'], hash_text['X']
            keypair_pk, epk = hash_text['keypair_pk'], hash_text['epk']
            c, sigma = hash_text['c'], hash_text['sigma']

            for i in range(trial):
                start = time()
                TRH.AdaptBM(mpk, p_prime)
                end = time()
                Temp = end - start
                T += Temp
            T = T / trial
            f.write(str(T) + ")\n")
            d += 10
        f.close()
    

    if Test_AdaptP:
        d=10      # number of attributes
        NN = 100
        print ("Adapt Bench")
        f = open('result_adaptP.txt', 'w+')
        while d <= NN:
            f.write("(" + str(d) + ",")
            T = 0
            Temp = 0
            start = 0
            end = 0
            S_test = {f'0{i+1}': str(i+1) for i in range(2*d)}
            sk = TRH.KeyGen(u_node, msk, mpk, S_test)
            print(S_test)
            policy_str=""
            for j in range(d):
                if j != d - 1:
                    policy_str += "( 0" + str(2*j + 1) + " and 0" + str(2*j + 2) + " )" + " or "
                else:
                    policy_str += "( 0" + str(2*j + 1) + " and 0" + str(2*j + 2) + " )"

            # 创建attri_list映射表
            W_attri_list = {f'0{i+1}': str(i+1) for i in range(2*d)}

            # 更新W字典
            W_test = {'policy': policy_str, 'T': W_attri_list}
            hash_text = TRH.Hash(mpk, m, W_test,mincover)

            p_prime, b, random_r = hash_text['p_prime'], hash_text['b'], hash_text['random_r']
            Cm, Ct = hash_text['Cm'], hash_text['Ct']
            Ck, K,WW, X = hash_text['Ck'], hash_text['K'], hash_text['WW'], hash_text['X']
            keypair_pk, epk = hash_text['keypair_pk'], hash_text['epk']
            c, sigma = hash_text['c'], hash_text['sigma']

            for i in range(trial):
                start = time()
                TRH.AdaptP(u_node,W_test,mpk,m,p_prime, b, random_r,sk,Ct,mincover)
                end = time()
                Temp = end - start
                T += Temp
            T = T / trial
            f.write(str(T) + ")\n")
            d += 10
        f.close()

    if Test_AdaptCM:
        d=10      # number of attributes
        NN = 100
        print ("Adapt Bench")
        f = open('result_adaptcm.txt', 'w+')
        while d <= NN:
            f.write("(" + str(d) + ",")
            T = 0
            Temp = 0
            start = 0
            end = 0
            S_test = {f'0{i+1}': str(i+1) for i in range(2*d)}
            sk = TRH.KeyGen(u_node, msk, mpk, S_test)
            print(S_test)
            policy_str=""
            for j in range(d):
                if j != d - 1:
                    policy_str += "( 0" + str(2*j + 1) + " and 0" + str(2*j + 2) + " )" + " or "
                else:
                    policy_str += "( 0" + str(2*j + 1) + " and 0" + str(2*j + 2) + " )"

            # 创建attri_list映射表
            W_attri_list = {f'0{i+1}': str(i+1) for i in range(2*d)}

            # 更新W字典
            W_test = {'policy': policy_str, 'T': W_attri_list}
            hash_text = TRH.Hash(mpk, m, W_test,mincover)

            p_prime, b, random_r = hash_text['p_prime'], hash_text['b'], hash_text['random_r']
            Cm, Ct = hash_text['Cm'], hash_text['Ct']
            Ck, K,WW, X = hash_text['Ck'], hash_text['K'], hash_text['WW'], hash_text['X']
            keypair_pk, epk = hash_text['keypair_pk'], hash_text['epk']
            c, sigma = hash_text['c'], hash_text['sigma']

            for i in range(trial):
                start = time()
                TRH.AdaptCM(u_node,W_test,mpk, sk, Cm,Ct, mincover, p_prime, b, random_r)
                end = time()
                Temp = end - start
                T += Temp
            T = T / trial
            f.write(str(T) + ")\n")
            d += 10
        f.close()


    if Test_Adapt2P:
        d=10      # number of attributes
        NN = 100
        print ("Adapt Bench")
        f = open('result_adapt2P.txt', 'w+')
        while d <= NN:
            f.write("(" + str(d) + ",")
            T = 0
            Temp = 0
            start = 0
            end = 0
            S_test = {f'0{i+1}': str(i+1) for i in range(2*d)}
            sk = TRH.KeyGen(u_node, msk, mpk, S_test)
            print(S_test)
            policy_str=""
            for j in range(d):
                if j != d - 1:
                    policy_str += "( 0" + str(2*j + 1) + " and 0" + str(2*j + 2) + " )" + " or "
                else:
                    policy_str += "( 0" + str(2*j + 1) + " and 0" + str(2*j + 2) + " )"

            # 创建attri_list映射表
            W_attri_list = {f'0{i+1}': str(i+1) for i in range(2*d)}

            # 更新W字典
            W_test = {'policy': policy_str, 'T': W_attri_list}
            hash_text = TRH.Hash(mpk, m, W_test,mincover)

            p_prime, b, random_r = hash_text['p_prime'], hash_text['b'], hash_text['random_r']
            Cm, Ct = hash_text['Cm'], hash_text['Ct']
            Ck, K,WW, X = hash_text['Ck'], hash_text['K'], hash_text['WW'], hash_text['X']
            keypair_pk, epk = hash_text['keypair_pk'], hash_text['epk']
            c, sigma = hash_text['c'], hash_text['sigma']

            for i in range(trial):
                start = time()
                TRH.Adapt2P(u_node,W_test,mpk, sk, Cm,Ct, Ck, K,mincover, p_prime, b, random_r)
                end = time()
                Temp = end - start
                T += Temp
            T = T / trial
            f.write(str(T) + ")\n")
            d += 10
        f.close()

    if Test_Trace:
        d=1000      # number of attributes
        NN = 10000
        print ("Trace Bench")
        f = open('result_trace.txt', 'w+')
        while d <= NN:
            f.write("(" + str(d) + ",")
            T = 0
            Temp = 0
            start = 0
            end = 0
            U_test = []
            for i in range(d):
                U_test.append(str(i))
            tree = Tree()
            list_u_id = tree.creatTree2(U_test)
            list_id_u = {val: key for key, val in list_u_id.items()}
            (mpk, msk, sk_tc, pk_tc) = TRH.Setup(tree)
            # 密钥生成
            u = f'{d-1}'
            id = list_u_id[u]
            u_node_list = tree.SearchU(tree.root, u)
            u_node = u_node_list[1]
            S = {'IDENTITY':'teacher', 'SEX':'female'}

            sk = TRH.KeyGen(u_node, msk, mpk, S)
            for i in range(trial):
                start = time()
                TRH.Trace(mpk, msk, R, list_id_u, sk)
                end = time()
                Temp = end - start
                T += Temp
                print(T)
            T = T / trial
            f.write(str(T) + ")\n")
            d += 1000
        f.close()

    X = msk['X']
    h = grp.random(ZR)
    X_h = {i: h * X[i] for i in X}

    if Test_CTUpdate:
        d=1000      # number of attributes
        NN = 10000
        print ("CT Update Bench")
        f = open('result_ctupdate.txt', 'w+')

        while d <= NN:
            f.write("(" + str(d) + ",")
            T = 0
            Temp = 0
            start = 0
            end = 0
            U_test = []
            for i in range(d):
                U_test.append(str(i))
            tree = Tree()
            list_u_id = tree.creatTree2(U_test)
            list_id_u = {val: key for key, val in list_u_id.items()}
            (mpk, msk, sk_tc, pk_tc) = TRH.Setup(tree)
            # 密钥生成
            u = f'{d-1}'
            id = list_u_id[u]
            u_node_list = tree.SearchU(tree.root, u)
            u_node = u_node_list[1]
            S = {'IDENTITY':'teacher', 'SEX':'female'}
            sk = TRH.KeyGen(u_node, msk, mpk, S)

            # 哈希生成
            policy = '(identity and sex)'
            attri_list = {'IDENTITY': 'teacher', 'SEX': 'female'}
            W = {'policy': policy, 'T':attri_list}
            m = grp.random(GT)
            R = []
            R_node = []
            for i in R:
                temp = tree.SearchU(tree.root, i)
                R_node.append(temp[1])  
            hash_text = TRH.Hash(mpk, m, W,mincover)
            mincover_prime,mincover_node = TRH.Trace(mpk, msk, R, list_id_u, sk)
            Ct = hash_text['Ct']
            
            X = msk['X']
            h = grp.random(ZR)
            X_h = {i: h * X[i] for i in X}
        
            for i in range(trial):
                start = time()
                TRH.CTUpdate(mpk,Ct['T'], X_h, mincover, mincover_prime,mincover_node)
                end = time()
                Temp = end - start
                T += Temp
                print(T)
            T = T / trial
            f.write(str(T) + ")\n")
            d += 1000
        f.close()

if __name__ == "__main__":
    debug = True
    main()
