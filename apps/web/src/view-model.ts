import type { FleetCounts, Host, Model, Provider } from "./api.js";
export interface DashboardSnapshot { counts:FleetCounts; hosts:readonly Host[]; providers:readonly Provider[]; models:readonly Model[] }
export const emptyCounts=():FleetCounts=>({hosts:0,active:0,degraded:0,offline:0,revoked:0,providers:0,models:0});
export function flattenInventory(hosts:readonly Host[],byHost:ReadonlyMap<string,{providers:readonly Provider[];models:readonly Model[]}>):DashboardSnapshot {let providers:Provider[]=[];const models:Model[]=[];for(const host of hosts){const inventory=byHost.get(host.hostId);if(inventory){providers.push(...inventory.providers);models.push(...inventory.models);}}providers.sort((a,b)=>a.providerId.localeCompare(b.providerId));models.sort((a,b)=>a.canonicalName.localeCompare(b.canonicalName)||a.modelId.localeCompare(b.modelId));const counts={hosts:hosts.length,active:hosts.filter(h=>h.health==="active").length,degraded:hosts.filter(h=>h.health==="degraded").length,offline:hosts.filter(h=>h.health==="offline").length,revoked:hosts.filter(h=>h.health==="revoked").length,providers:providers.length,models:models.length};return{counts,hosts:Object.freeze([...hosts]),providers:Object.freeze(providers),models:Object.freeze(models)};}

export type PlatformFilter="linux"|"darwin"|"windows"|"all";
export type HealthFilter="active"|"degraded"|"offline"|"revoked"|"all";
export type HostSortField="displayName"|"platform"|"health"|"modelCount"|"providerCount"|"observedAt";
export type HostSortDir="asc"|"desc";
export interface HostFilter { platform:PlatformFilter; health:HealthFilter; query:string }
export interface HostSort { field:HostSortField; dir:HostSortDir }
export const emptyHostFilter=():HostFilter=>({platform:"all",health:"all",query:""});
export const defaultHostSort=():HostSort=>({field:"displayName",dir:"asc"});

const HEALTH_RANK:Record<Host["health"],number>={active:0,degraded:1,offline:2,revoked:3};
function byField(field:HostSortField,dir:HostSortDir):(a:Host,b:Host)=>number{
  return (a:Host,b:Host)=>{
    let primary:number;
    switch(field){
      case "displayName": primary=a.displayName.localeCompare(b.displayName); break;
      case "platform": primary=a.platform.localeCompare(b.platform); break;
      case "health": primary=HEALTH_RANK[a.health]-HEALTH_RANK[b.health]; break;
      case "modelCount": primary=a.modelCount-b.modelCount; break;
      case "providerCount": primary=a.providerCount-b.providerCount; break;
      case "observedAt": primary=a.observedAt.localeCompare(b.observedAt); break;
      default: primary=0;
    }
    if(primary!==0)return dir==="asc"?primary:-primary;
    return a.hostId.localeCompare(b.hostId);
  };
}
export function compareHosts(a:Host,b:Host,sort:HostSort):number{ return byField(sort.field,sort.dir)(a,b); }

export function filterAndSortHosts(hosts:readonly Host[],filter:HostFilter,sort:HostSort):Host[]{
  const platform=filter.platform,health=filter.health,raw=filter.query.trim().toLowerCase();
  const scoped=hosts.filter(h=>(platform==="all"||h.platform===platform)&&(health==="all"||h.health===health));
  const query=(raw.length>0?scoped.filter(h=>h.displayName.toLowerCase().includes(raw)||h.hostId.toLowerCase().includes(raw)):scoped);
  return query.map(h=>({...h})).sort((a,b)=>byField(sort.field,sort.dir)(a,b));
}

export function relativeTime(iso:string,now=Date.now()):string {const value=Date.parse(iso);if(!Number.isFinite(value))return"Unknown";const seconds=Math.max(0,Math.floor((now-value)/1000));if(seconds<60)return`${seconds}s ago`;const minutes=Math.floor(seconds/60);if(minutes<60)return`${minutes}m ago`;const hours=Math.floor(minutes/60);return hours<48?`${hours}h ago`:`${Math.floor(hours/24)}d ago`;}
