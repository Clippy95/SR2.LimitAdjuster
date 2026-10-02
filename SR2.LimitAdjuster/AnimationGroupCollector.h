#pragma once
#include <algorithm>
#include <cstdint>
#include <vector>

namespace AnimationGroupCollector {
constexpr unsigned kOutputCapacity = 100;
constexpr unsigned kAnimationCapacity = 10240;
struct Result {
    std::vector<uint32_t> files;
    unsigned uniqueAnimations = 0;
    bool valid = true;
};
template<class Memory>
Result Collect(Memory& m, uint32_t firstGroup) {
    Result result;
    std::vector<uint32_t> pending{firstGroup}, groups, animations;
    auto appendTag = [&](uint32_t tag, bool state) {
        if (tag == UINT32_MAX || (state && tag == 1)) return;
        if (tag >= (state ? 676u : 1337u)) { result.valid=false; return; }
        uint32_t node = m.chain(state,tag);
        unsigned visited = 0;
        while(node) {
            if(++visited > kAnimationCapacity) { result.valid=false; return; }
            const auto animation=m.read32(node);
            if(!m.validAnimation(animation)) { result.valid=false; return; }
            if(std::find(animations.begin(),animations.end(),animation)==animations.end()) {
                if(animations.size()==kAnimationCapacity) { result.valid=false; return; }
                animations.push_back(animation);
                if(!m.permanent(animation)) result.files.push_back(m.read32(animation));
            }
            node=m.read32(node+4);
        }
    };
    while(!pending.empty() && result.valid) {
        const auto group=pending.back();pending.pop_back();
        if(!m.validGroup(group)) { result.valid=false; break; }
        if(std::find(groups.begin(),groups.end(),group)!=groups.end()) continue;
        groups.push_back(group);
        if(m.read32(group+28)&0x40) {
            const auto base=m.objectBase(m.read32(group+32));
            if(!base) { result.valid=false; break; }
            const auto count=m.read32(base), entries=m.read32(base+4);
            if(count>m.groupCount()) { result.valid=false; break; }
            for(unsigned i=count;i>0;--i) {
                const auto index=m.read32(entries+(i-1)*84+80);
                if(index>=m.groupCount()) { result.valid=false; break; }
                pending.push_back(m.groupAddress(index));
            }
            continue;
        }
        const auto npcCount=m.read8(group+72);
        if(npcCount>4) { result.valid=false; break; }
        for(unsigned i=0;i<npcCount && result.valid;++i) {
            const auto npc=m.read32(group+56+i*4);
            if(!npc) { result.valid=false; break; }
            for(unsigned off:{12u,16u,20u}) appendTag(m.read32(npc+off),false);
            const auto cowerCount=m.read32(npc+124), motionCount=m.read32(npc+120);
            if(cowerCount>3 || motionCount>4) { result.valid=false; break; }
            for(unsigned j=0;j<cowerCount;++j) appendTag(m.read32(npc+128+j*4),true);
            for(unsigned j=0;j<motionCount;++j) {
                const auto motion=npc+24+j*24, actionCount=m.read32(motion+20);
                if(actionCount>4) { result.valid=false; break; }
                appendTag(m.read32(motion),true);
                for(unsigned k=0;k<actionCount;++k) appendTag(m.read32(motion+4+k*4),false);
            }
        }
    }
    result.uniqueAnimations=static_cast<unsigned>(animations.size());
    return result;
}
template<class Memory>
bool Copy(Memory& m,uint32_t group,uint32_t* output,int* count,Result* details=nullptr) {
    if(!output || !count) return false;
    *count=0;
    auto result=Collect(m,group);
    const bool okay=result.valid && result.files.size()<=kOutputCapacity;
    if(okay) {
        std::copy(result.files.begin(),result.files.end(),output);
        *count=static_cast<int>(result.files.size());
    }
    if(details) *details=std::move(result);
    return okay;
}
}
