from backend.app.agents.qlearning import QLearningAgent
from backend.app.environment.securecode import SecureCodeEnv, Rewards


def fit(records, config, seed):
    if config['episodes'] < 1:
        raise ValueError('episodes must be positive')
    env = SecureCodeEnv(records, config['max_steps'], Rewards(**config['rewards']))
    agent = QLearningAgent(env.observation_space.n, seed=seed, **{k:config[k] for k in ('alpha','gamma','epsilon','epsilon_min','epsilon_decay')})
    history=[]
    for episode in range(config['episodes']):
        state,_ = env.reset(seed=seed if episode==0 else None)
        total=0
        while not env.done:
            action=agent.act(state)
            nxt,reward,terminated,truncated,_=env.step(action)
            agent.update(state,action,reward,nxt,terminated or truncated)
            state=nxt
            total+=reward
        history.append(dict(episode=episode+1,reward=total,epsilon=agent.epsilon,
                            validated=int(env.security_verified),steps=env.steps))
        agent.decay()
    return agent,history,env
