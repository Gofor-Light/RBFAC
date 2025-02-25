from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, GT, pair
from charm.toolbox.secretutil import SecretUtil
from datetime import datetime
from msp import MSP
from Cover import *
from AES import *



class RBFAC:
    def __init__(self, groupObj, verbose=False):
        self.group = groupObj
        self.util = MSP(self.group, verbose)

    # authority: input(lamda, A, T)
    def Setup(self, tree):
        '''
        :param tree: 系统的用户树
        :return: 返回公钥(PP),私钥(MSK),TC秘钥(sk_tc),TC公钥(pk_tc)
        '''
        
        # 随机生成必要的参数
        g = self.group.random(G1)
        p = self.group.random(G1)
        a = self.group.random(ZR)
        alpha = self.group.random(ZR)
        h = self.group.random(G1)
        u = self.group.random(G1)

        # 初始化用于存储的字典，避免多次创建字典
        X = {}
        Y = {}
        self.preOrderTraversal(tree.root, X, Y, g)

        # 随机生成秘钥
        K_temp = self.group.random(ZR)
        K = self.group.serialize(K_temp).decode('UTF-8')
        k = K[:32]  

        # 计算公钥部分
        egg_alpha = pair(g, g) ** alpha
        g_a = g ** a
        sk_tc = self.group.random(ZR)
        pk_tc = g ** sk_tc

        # 返回公钥和私钥
        PP = {
            "p": p,
            "g": g,
            "h": h,
            "u": u,
            "egg_alpha": egg_alpha,
            "g_a": g_a,
            "Y": Y,
            "Tree": tree
        }
        MSK = {
            "a": a,
            "alpha": alpha,
            "X": X,
            "k": k
        }
        return PP, MSK, sk_tc, pk_tc


    # python在函数里传入列表 字典会改变他们的值
    def preOrderTraversal(self, Root, X, Y, g):
        '''
        :param Root: 树的根节点
        :param X: 保存树中每个节点的私钥部分-随机数
        :param Y: 保存树中每个节点的公钥部分
        :param g: 生成元
        :return: 递归把x,y存在字典里
        '''
        if Root == None:
            return
        xi = self.group.random(ZR)

        X[Root.id] = xi
        Y[Root.id] = g ** xi
        self.preOrderTraversal(Root.lchild, X, Y, g)
        self.preOrderTraversal(Root.rchild, X, Y, g)

    def KeyGen(self, u_node, msk, pk, S):

        g = pk['g']
        a = msk['a']
        k = msk['k']
        id = u_node.id
        cipher = encrypt_AES(str(id), k)
        c = self.group.hash(cipher, ZR)
        r = self.group.random(ZR)

        # K2 直接赋值
        K2 = c

        # 计算 K 和 L
        K = g ** (msk['alpha'] / (a + c)) * pk['h'] ** r
        L = g ** r
        L2 = g ** (a * r)

        K_tao = {}
        for key, value in S.items():
            s_tao = self.group.hash(value, ZR)
            # v 的计算只用一次 g 的幂运算，合并操作
            v = g ** (s_tao * r) / pk['u'] ** ((a + c) * r)
            K_tao[key] = v

        X_i = {}

        Tree = pk['Tree']
        path = Tree.getPath(u_node)
        # 将 X_i 的构造合并成一个循环
        for i in path:
            X_i[i] = msk['X'][i]

        K_u = g ** (r / X_i[id])

        SK = {
            'K2': K2,
            'K': K,
            'L': L,
            'L2': L2,
            'K_u': K_u,
            'K_tao': K_tao,
            'X_i': X_i,
            'S': S,
            'r': r,
            'c': c,
            'cipher': cipher
        }
        return SK

    def Encrypt(self, PP, m, W,mincover):
        '''
        :param PP: 系统公共参数
        :param m: 需要加密的明文
        :param W: 访问控制方案，包括属性和属性值
        :param R: 撤销列表
        :return: 返回加密后的密文，其中包括部分访问策略
        '''

        policy = self.util.createPolicy(W['policy'])
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        num_cols = self.util.len_longest_row

        # Generate random values for v in one step
        v = [self.group.random(ZR) for _ in range(num_cols)]
        s = v[0]

        C = m * PP['egg_alpha'] ** s
        C0 = PP['g'] ** s
        C02 = PP['g_a'] ** s

        Ci1, Ci2, Ci3, lamda_i_list = {}, {}, {}, {}

        for attr, row in mono_span_prog.items():
            lamda_i = sum(row[i] * v[i] for i in range(len(row)))
            lamda_i_list[attr] = lamda_i
            t_i = self.group.random(ZR)
            
            # Compute C1, C2, C3 in one go
            C1 = (PP['h'] ** lamda_i) * (PP['u'] ** t_i)
            attr_stripped = self.util.strip_index(attr)
            attr_value_ZR = self.group.hash(W['T'][attr_stripped], ZR)
            C2 = PP['g'] ** (-t_i * attr_value_ZR + lamda_i)
            C3 = PP['g'] ** t_i

            Ci1[attr], Ci2[attr], Ci3[attr] = C1, C2, C3

        T = {}
        # Optimize T construction
        T = {node: PP['Y'][node] ** s for node in mincover}

        CT = {
            'C': C,
            'C0': C0,
            'C02': C02,
            'Ci1': Ci1,
            'Ci2': Ci2,
            'Ci3': Ci3,
            'W_': W['policy'],
            'T': T
        }
        return CT

    # # m不加密 自由修改编辑策略
    # def Hash(self, mpk, m, W,mincover):
        
    #     # step 1 计算哈希值
    #     g = mpk['g']
    #     random_r = self.group.random(ZR)
    #     R = self.group.random(GT)
    #     e = self.group.hash(str(R), ZR)
    #     p_prime = g**e
    #     b = g**random_r * p_prime**self.group.hash(str(m), ZR)

    #     # step 2 加密陷门
    #     Ct = self.Encrypt(mpk, R, W,mincover)

    #     # step 3 生成签名
    #     keypair_sk = self.group.random(ZR)
    #     keypair_pk = g**keypair_sk
    #     esk = self.group.random(ZR)
    #     epk = g**esk
    #     c = g**(keypair_sk + e) 
    #     sigma = esk + keypair_sk * self.group.hash((str(epk)+str(c)), ZR)

    #     return {
    #         'Cm':m,
    #         'Ct':Ct,
    #         'p_prime':p_prime,
    #         'b':b,
    #         'random_r':random_r,
    #         'c':c,
    #         'epk':epk,
    #         'keypair_pk':keypair_pk,
    #         'sigma': sigma
    #     }

    # m加密  提供高级策略 

    # 三次加密
    def Encrypt3(self, PP, sk,t,k, Wm,Wt,Wk,mincover):
        '''
        :param PP: 系统公共参数
        :param sk t k: 需要加密的明文
        :param W: 访问控制方案，包括属性和属性值
        :param R: 撤销列表
        :return: 返回加密后的密文，其中包括部分访问策略
        '''

        policy = self.util.createPolicy(Wm['policy'])
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        num_cols = self.util.len_longest_row

        # Generate random values for v in one step
        v = [self.group.random(ZR) for _ in range(num_cols)]
        sm = v[0]

        C = sk * PP['egg_alpha'] ** sm
        C0 = PP['g'] ** sm
        C02 = PP['g_a'] ** sm

        Ci1, Ci2, Ci3, lamda_i_list = {}, {}, {}, {}

        for attr, row in mono_span_prog.items():
            lamda_i = sum(row[i] * v[i] for i in range(len(row)))
            lamda_i_list[attr] = lamda_i
            t_i = self.group.random(ZR)
            
            # Compute C1, C2, C3 in one go
            C1 = (PP['h'] ** lamda_i) * (PP['u'] ** t_i)
            attr_stripped = self.util.strip_index(attr)
            attr_value_ZR = self.group.hash(Wm['T'][attr_stripped], ZR)
            C2 = PP['g'] ** (-t_i * attr_value_ZR + lamda_i)
            C3 = PP['g'] ** t_i

            Ci1[attr], Ci2[attr], Ci3[attr] = C1, C2, C3

        T = {node: PP['Y'][node] ** sm for node in mincover}

        Cs = {
            'C': C,
            'C0': C0,
            'C02': C02,
            'Ci1': Ci1,
            'Ci2': Ci2,
            'Ci3': Ci3,
            'W_': Wm['policy'],
            'T': T
        }

        policy = self.util.createPolicy(Wt['policy'])
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        num_cols = self.util.len_longest_row

        # Generate random values for v in one step
        v = [self.group.random(ZR) for _ in range(num_cols)]
        st = v[0]

        C = t * PP['egg_alpha'] ** st
        C0 = PP['g'] ** st
        C02 = PP['g_a'] ** st

        Ci1, Ci2, Ci3, lamda_i_list = {}, {}, {}, {}

        for attr, row in mono_span_prog.items():
            lamda_i = sum(row[i] * v[i] for i in range(len(row)))
            lamda_i_list[attr] = lamda_i
            t_i = self.group.random(ZR)
            
            # Compute C1, C2, C3 in one go
            C1 = (PP['h'] ** lamda_i) * (PP['u'] ** t_i)
            attr_stripped = self.util.strip_index(attr)
            attr_value_ZR = self.group.hash(Wt['T'][attr_stripped], ZR)
            C2 = PP['g'] ** (-t_i * attr_value_ZR + lamda_i)
            C3 = PP['g'] ** t_i

            Ci1[attr], Ci2[attr], Ci3[attr] = C1, C2, C3

        T = {node: PP['Y'][node] ** st for node in mincover}

        Ct = {
            'C': C,
            'C0': C0,
            'C02': C02,
            'Ci1': Ci1,
            'Ci2': Ci2,
            'Ci3': Ci3,
            'W_': Wt['policy'],
            'T': T
        }

        policy = self.util.createPolicy(Wk['policy'])
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        num_cols = self.util.len_longest_row

        # Generate random values for v in one step
        v = [self.group.random(ZR) for _ in range(num_cols)]
        sk = v[0]

        C = k * PP['egg_alpha'] ** sk
        C0 = PP['g'] ** sk
        C02 = PP['g_a'] ** sk

        Ci1, Ci2, Ci3, lamda_i_list = {}, {}, {}, {}

        for attr, row in mono_span_prog.items():
            lamda_i = sum(row[i] * v[i] for i in range(len(row)))
            lamda_i_list[attr] = lamda_i
            t_i = self.group.random(ZR)
            
            # Compute C1, C2, C3 in one go
            C1 = (PP['h'] ** lamda_i) * (PP['u'] ** t_i)
            attr_stripped = self.util.strip_index(attr)
            attr_value_ZR = self.group.hash(Wk['T'][attr_stripped], ZR)
            C2 = PP['g'] ** (-t_i * attr_value_ZR + lamda_i)
            C3 = PP['g'] ** t_i

            Ci1[attr], Ci2[attr], Ci3[attr] = C1, C2, C3

        T = {node: PP['Y'][node] ** sk for node in mincover}

        Ck = {
            'C': C,
            'C0': C0,
            'C02': C02,
            'Ci1': Ci1,
            'Ci2': Ci2,
            'Ci3': Ci3,
            'W_': Wk['policy'],
            'T': T
        }
        return Cs,Ct,Ck
    def Hash(self, mpk, m, W,mincover):

        # step 1 加密消息
        # sk = self.group.random(GT)
        # sk_temp = str(sk)[:32]
        # Cm = encrypt_AES(str(m), sk_temp)

        
        # R = self.group.random(GT)
        # k = self.group.random(GT)
        # # Note that `sk`, `R`, and `k` are encrypted separately 
        # # to simulate the encryption of `sk`, `sk||R`, and `sk||R||k`.
        # Cs,Ct,Ck = self.Encrypt3(mpk,sk,R,k,W,W,W,mincover) 

        R = self.group.random(GT)
        k = self.group.random(GT)
        Cm,Ct,Ck = self.Encrypt3(mpk,m,R,k,W,W,W,mincover)

        # step 2 计算哈希值
        g = mpk['g']
        random_r = self.group.random(ZR)
        e = self.group.hash(str(R), ZR)
        p_prime = g**e
        b = g**random_r * p_prime**self.group.hash(str(Cm), ZR)

        # step 3 生成证明信息
        K = g**self.group.hash(str(k), ZR)
        x = self.group.random(ZR)
        X = mpk['g'] ** x
        k_hash = self.group.hash(str(k), ZR)
        K_hash = self.group.hash((str(X) + str(K)), ZR)
        WW = x + k_hash * K_hash

        # step 4 生成签名
        keypair_sk = self.group.random(ZR)
        keypair_pk = g**keypair_sk
        esk = self.group.random(ZR)
        epk = g**esk
        c = g**(keypair_sk + e) 
        sigma = esk + keypair_sk * self.group.hash((str(epk)+str(c)), ZR)

        return {
            'Cm':Cm,
            #'Cs':Cs,
            'Ct':Ct,
            'Ck':Ck,
            'K':K,
            'WW':WW,
            'X':X,
            'p_prime':p_prime,
            'b':b,
            'random_r':random_r,
            'c':c,
            'epk':epk,
            'keypair_pk':keypair_pk,
            'sigma': sigma
        }

    def Verify(self, mpk, Cm, p_prime, b, random_r, c, epk, sigma, keypair_pk, WW, K, X):
        g = mpk['g']
        g_message_p_prime_r = g**random_r * p_prime**self.group.hash(str(Cm), ZR)
        epk_pk = epk * keypair_pk**self.group.hash(str(epk)+str(c), ZR)
        # print("\nVerify() result:  ", (b == g_message_p_prime_r) and (g**sigma == epk_pk) and is_valid)
        return (b == g_message_p_prime_r) and (g**sigma == epk_pk) and (g ** WW == X * K ** self.group.hash((str(X) + str(K)), ZR))

    def VerifyM(self, mpk, m, p_prime, b, random_r, c, epk, sigma, keypair_pk, WW, K, X):
        g = mpk['g']
        g_message_p_prime_r = g**random_r * p_prime**self.group.hash(str(m), ZR)
        epk_pk = epk * keypair_pk**self.group.hash(str(epk)+str(c), ZR)
        # print("\nVerify() result:  ", (b == g_message_p_prime_r) and (g**sigma == epk_pk) and is_valid)
        return (b == g_message_p_prime_r) and (g**sigma == epk_pk) and (g ** WW == X * K ** self.group.hash((str(X) + str(K)), ZR))


    def TKGen(self, mpk, sk_tc, pk_tc, req_tk):
        g = mpk['g']
        r = self.group.random(ZR)
        R = g**r
        sigma_tc = r + sk_tc * self.group.hash(str(R)+str(pk_tc)+str(req_tk)+str(self.deposit))
        self.ed_tk = [req_tk, sigma_tc, R, datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')]
        return self.ed_tk

    def verifyTK(self, mpk, pri_tk, pk_tc):
        g = mpk['g']
        req_tk = pri_tk[0]
        sigma_tc = pri_tk[1]
        R = pri_tk[2]
        deposit = self.deposit

        # 使用字典简化条件判断
        token_mapping = {
            "T_1tk": 'T_1m',
            "T_ntk": 'T_nm',
            "B_1tk": 'B_1m',
            "B_ntk": 'B_nm'
        }
        
        token_type = pri_tk[0][0]
        if token_type in token_mapping:
            pri_tk.append(token_mapping[token_type])

        # 提取相同的哈希计算
        hash_input = str(R) + str(pk_tc) + str(req_tk) + str(deposit)
        hash_value = self.group.hash(hash_input)

        g_sigma_tc = R * pk_tc ** hash_value
        is_valid = g ** sigma_tc == g_sigma_tc
        print("Token verification result: ", is_valid)
        return is_valid

    def Decrypt(self, u_node, pk, CT, SK,mincover):

        user_atts = list(SK['S'].keys())
        policy = self.util.createPolicy(CT['W_'])
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        
        pruned = self.util.prune(policy, user_atts)
        if not pruned:
            raise Exception("Don't have the required attributes for decryption!")

        Tree = pk['Tree']
        path = Tree.getPath(u_node)
        coverList = set(mincover)

        j = [i for i in path if i in coverList]
        if not j:  # 防止空列表索引
            raise Exception("No valid index found in cover list.")
            
        x_j = SK['X_i'][j[0]]
        x_id = SK['X_i'][path[-1]]
        theta = x_id / x_j
        B = pair(SK['K_u'], CT['T'][j[0]]) ** theta

        F = 1
        for i in pruned:
            # attention:type(i) = binnode
            x = i.getAttributeAndIndex()
            y = i.getAttribute()
            i_str = str(i)
            a = pair((SK['L'] ** SK['K2']) * SK['L2'], CT['Ci1'][i_str])
            b = pair(SK['L'], CT['Ci2'][i_str])
            c = pair(SK['K_tao'][i_str], CT['Ci3'][i_str])
            F *= (a * b * c)

        D = pair(SK['K'], CT['C0'] ** SK['K2'] * CT['C02'])
        m = (CT['C'] * F) / (D * B)
        
        return m

    # 三次解密
    def Decrypt3(self, u_node, pk, Cm,Ct,Ck,SK,mincover):

        user_atts = list(SK['S'].keys())
        policy = self.util.createPolicy(Cm['W_'])
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        
        pruned = self.util.prune(policy, user_atts)
        if not pruned:
            raise Exception("Don't have the required attributes for decryption!")

        Tree = pk['Tree']
        path = Tree.getPath(u_node)
        coverList = set(mincover)

        j = [i for i in path if i in coverList]
        if not j:  # 防止空列表索引
            raise Exception("No valid index found in cover list.")
            
        x_j = SK['X_i'][j[0]]
        x_id = SK['X_i'][path[-1]]
        theta = x_id / x_j
        B = pair(SK['K_u'], Cm['T'][j[0]]) ** theta

        F = 1
        for i in pruned:
            # attention:type(i) = binnode
            x = i.getAttributeAndIndex()
            y = i.getAttribute()
            i_str = str(i)
            a = pair((SK['L'] ** SK['K2']) * SK['L2'], Cm['Ci1'][i_str])
            b = pair(SK['L'], Cm['Ci2'][i_str])
            c = pair(SK['K_tao'][i_str], Cm['Ci3'][i_str])
            F *= (a * b * c)

        D = pair(SK['K'], Cm['C0'] ** SK['K2'] * Cm['C02'])
        m = (Cm['C'] * F) / (D * B)

        policy = self.util.createPolicy(Ct['W_'])
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        
        pruned = self.util.prune(policy, user_atts)
        if not pruned:
            raise Exception("Don't have the required attributes for decryption!")
            
        B = pair(SK['K_u'], Ct['T'][j[0]]) ** theta

        F = 1
        for i in pruned:
            # attention:type(i) = binnode
            x = i.getAttributeAndIndex()
            y = i.getAttribute()
            i_str = str(i)
            a = pair((SK['L'] ** SK['K2']) * SK['L2'], Ct['Ci1'][i_str])
            b = pair(SK['L'], Ct['Ci2'][i_str])
            c = pair(SK['K_tao'][i_str], Ct['Ci3'][i_str])
            F *= (a * b * c)

        D = pair(SK['K'], Ct['C0'] ** SK['K2'] * Ct['C02'])
        t = (Ct['C'] * F) / (D * B)

        policy = self.util.createPolicy(Ck['W_'])
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        
        pruned = self.util.prune(policy, user_atts)
        if not pruned:
            raise Exception("Don't have the required attributes for decryption!")
            
        B = pair(SK['K_u'], Ck['T'][j[0]]) ** theta

        F = 1
        for i in pruned:
            # attention:type(i) = binnode
            x = i.getAttributeAndIndex()
            y = i.getAttribute()
            i_str = str(i)
            a = pair((SK['L'] ** SK['K2']) * SK['L2'], Ck['Ci1'][i_str])
            b = pair(SK['L'], Ck['Ci2'][i_str])
            c = pair(SK['K_tao'][i_str], Ck['Ci3'][i_str])
            F *= (a * b * c)

        D = pair(SK['K'], Ck['C0'] ** SK['K2'] * Ck['C02'])
        k = (Ck['C'] * F) / (D * B)   

        return m,t,k


    # 非加密场景 编辑消息及自由修改编辑策略
    def AdaptP(self, u_node, W, mpk,m,p_prime, b, random_r, sk,Ct,mincover):
        
        # step 1 解密陷门
        R = self.Decrypt(u_node, mpk, Ct, sk,mincover)
        e = self.group.hash(str(R), ZR)

        # step 2 生成新消息
        m_prime = self.group.random(GT)
        
        # step 3 计算random_r_prime
        m_hash = self.group.hash(str(m), ZR)
        m_prime_hash = self.group.hash(str(m_prime), ZR)
        random_r_prime = random_r + (m_hash - m_prime_hash) * e

        # step 4 加密陷门
        Ct_prime = self.Encrypt(mpk, R, W,mincover)

        # step 5 生成新签名
        keypair_sk_prime = self.group.random(ZR)
        keypair_pk_prime = mpk['g'] ** keypair_sk_prime
        esk_prime = self.group.random(ZR)
        epk_prime = mpk['g'] ** esk_prime
        c_prime = mpk['g'] ** (keypair_sk_prime + self.group.hash(str(R), ZR))
        
        # 添加缓存避免重复计算
        sigma_prime = esk_prime + keypair_sk_prime * self.group.hash((str(epk_prime) + str(c_prime)), ZR)
       
        return {
            'm_prime': m_prime, 
            'p_prime': p_prime, 
            'b': b, 
            'random_r_prime': random_r_prime, 
            'Ct_prime': Ct_prime, 
            'c_prime': c_prime, 
            'epk_prime': epk_prime, 
            'sigma_prime': sigma_prime,
            'keypair_pk_prime': keypair_pk_prime,
        }
    # 加密场景修改消息
    def AdaptCM(self, u_node, W, mpk, sk, Cm, Ct,mincover, p_prime, b, random_r):
        
        # step 1 解密
        m = self.Decrypt(u_node, mpk, Cm, sk,mincover)
        R = self.Decrypt(u_node, mpk, Ct, sk,mincover)
        
        # step 2 加密新消息
        e = self.group.hash(str(R), ZR)
        Cm_prime = self.Encrypt(mpk, m, W,mincover)

        # step 3
        Cm_C_hash = self.group.hash(str(Cm), ZR)
        Cm_prime_C_hash = self.group.hash(str(Cm_prime), ZR)
        random_r_prime = random_r + (Cm_C_hash - Cm_prime_C_hash) * e

        # step 4
        keypair_sk_prime = self.group.random(ZR)
        keypair_pk_prime = mpk['g'] ** keypair_sk_prime
        esk_prime = self.group.random(ZR)
        epk_prime = mpk['g'] ** esk_prime
        c_prime = mpk['g'] ** (keypair_sk_prime + self.group.hash(str(R), ZR))
        sigma_prime = esk_prime + keypair_sk_prime * self.group.hash((str(epk_prime) + str(c_prime)), ZR)
       
        return {
            'Cm_prime': Cm_prime, 
            'p_prime': p_prime, 
            'b': b, 
            'random_r_prime': random_r_prime, 
            'c_prime': c_prime, 
            'epk_prime': epk_prime, 
            'sigma_prime': sigma_prime,
            'keypair_pk_prime': keypair_pk_prime
        }

    # 加密场景 修改可读性策略及编辑策略
    def Adapt2P(self, u_node, W, mpk, sk, Cm, Ct, Ck, K,mincover, p_prime, b, random_r):
        
        # step 1 解密
        m,R,k = self.Decrypt3(u_node, mpk, Cm,Ct,Ck,sk,mincover)
        
        # step 2 生成证明
        x = self.group.random(ZR)
        X = mpk['g'] ** x
        k_hash = self.group.hash(str(k), ZR)
        K_hash = self.group.hash((str(X) + str(K)), ZR)
        WW = x + k_hash * K_hash
        
        # step 3
        e = self.group.hash(str(R), ZR)
        Cm_prime = self.Encrypt(mpk, m, W,mincover)
        
        Cm_C_hash = self.group.hash(str(Cm), ZR)
        Cm_prime_C_hash = self.group.hash(str(Cm_prime), ZR)
        random_r_prime = random_r + (Cm_C_hash - Cm_prime_C_hash) * e

        # step 4
        Ct_prime = self.Encrypt(mpk, R, W,mincover)

        # step 5
        keypair_sk_prime = self.group.random(ZR)
        keypair_pk_prime = mpk['g'] ** keypair_sk_prime
        esk_prime = self.group.random(ZR)
        epk_prime = mpk['g'] ** esk_prime
        c_prime = mpk['g'] ** (keypair_sk_prime + self.group.hash(str(R), ZR))
        sigma_prime = esk_prime + keypair_sk_prime * self.group.hash((str(epk_prime) + str(c_prime)), ZR)
       
        return {
            'Cm_prime': Cm_prime, 
            'Ct_prime': Ct_prime, 
            'p_prime': p_prime, 
            'b': b, 
            'random_r_prime': random_r_prime, 
            'c_prime': c_prime, 
            'epk_prime': epk_prime, 
            'sigma_prime': sigma_prime,
            'keypair_pk_prime': keypair_pk_prime,
            'WW': WW,
            'X': X
        }

    def KeySanityCheck(self, sk, pp):
        # first
        if not all(self.group.ismember(key) for key in [sk['K2'], sk['K'], sk['L'], sk['L2'], sk['K_u']]):
            return False

        if not all(self.group.ismember(i) for i in sk['K_tao'].values()):
            return False

        # second
        temp = pair(pp['g_a'], sk['L'])
        if not (pair(pp['g'], sk['L2']) == temp and temp != 1):
            return False

        # third
        temp = pair(sk['K'], pp['g_a'] * (pp['g'] ** sk['K2']))
        if not (temp == pp['egg_alpha'] * pair((sk['L'] ** sk['K2']) * sk['L2'], pp['h']) and temp != 1):
            return False

        # fourth
        for key, value in sk['S'].items():
            s_tao = self.group.hash(value, ZR)
            temp = pair(sk['L'], pp['g']) ** s_tao
            if not (pair(sk['K_tao'][key], pp['g']) * pair((sk['L'] ** sk['K2']) * sk['L'], pp['u']) and temp != 1):
                return False
                
        return True

    def Trace(self, mpk, msk, R, u_node_list, sk):
        cipher = decrypt_AES(sk['cipher'], msk['k'])
        id = int(cipher)
        u = u_node_list[id]
        if u not in R:
            R.append(u)
        R_node = []
        tree = mpk['Tree']
        for i in R:
            temp = tree.SearchU(tree.root, i)
            R_node.append(temp[1])
        mincover,mincover_node = cover(tree, R_node) 
        print("mincover:", mincover)
        return mincover,mincover_node

    def CTUpdate(self, mpk, T, X_h, mincover, mincover_prime,mincover_node):
        # 更新T
        T_prime = {}
        tree = mpk['Tree']
        mincover_set = set(mincover)
        for i,v in enumerate(mincover_prime):
            if v in mincover_set:
                T_prime[v] = T[v]
            else: 
                path = tree.getPath(mincover_node[i])
                # print("path:", path)
                j = next((k for k, kv in enumerate(path) if kv in mincover_set), None)
                path = path[j:]
                Yj = T[path[0]]
                for k in range(len(path)-1):
                    Yj = Yj**(X_h[path[k+1]]/X_h[path[k]])
                T_prime[v] = Yj
        # print("T_prime:", T_prime)
        return T_prime

    # 交易级别编辑消息
    def AdaptM(self, u_node,sk, mpk, m, p_prime, b, random_r, Ct,mincover):
        
        # step 1 解密陷门
        R = self.Decrypt(u_node, mpk, Ct, sk,mincover)
        e = self.group.hash(str(R), ZR)

        # step 2 生成新消息
        m_prime = self.group.random(GT)
        
        # step 3 计算random_r_prime
        m_hash = self.group.hash(str(m), ZR)
        m_prime_hash = self.group.hash(str(m_prime), ZR)
        random_r_prime = random_r + (m_hash - m_prime_hash) * e

        # step 4 生成新签名
        keypair_sk_prime = self.group.random(ZR)
        keypair_pk_prime = mpk['g'] ** keypair_sk_prime
        esk_prime = self.group.random(ZR)
        epk_prime = mpk['g'] ** esk_prime
        c_prime = mpk['g'] ** (keypair_sk_prime + self.group.hash(str(R), ZR))
        epk_prime_hash = self.group.hash((str(epk_prime) + str(c_prime)), ZR)
        sigma_prime = esk_prime + keypair_sk_prime * epk_prime_hash
        
        return {
            'm_prime': m_prime, 
            'p_prime': p_prime, 
            'b': b, 
            'random_r_prime': random_r_prime, 
            'c_prime': c_prime, 
            'epk_prime': epk_prime, 
            'sigma_prime': sigma_prime,
            'keypair_pk_prime': keypair_pk_prime
        }

    # 区块级别编辑消息
    def AdaptBM(self, mpk,p_prime):
        
        # step 2 生成新消息
        m_prime = self.group.random(GT)
        
        # step 3 计算random_r_prime
        g = mpk['g']
        random_r_prime = self.group.random(ZR)
        b = g**random_r_prime * p_prime**self.group.hash(str(m_prime), ZR)
        
        return {
            'm_prime': m_prime, 
            'p_prime': p_prime, 
            'b': b, 
            'random_r_prime': random_r_prime, 
        }